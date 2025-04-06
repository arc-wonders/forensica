import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import re
import networkx as nx
from collections import Counter, defaultdict
from datetime import datetime

class ForensicMetadataAnalyzer:
    def __init__(self):
        self.data = None
        self.df = None
        self.threat_items = []
        self.safe_items = []
        self.correlations = {}
        self.tag_graph = None
        
    def load_json_data(self, json_data):
        """Load metadata from JSON string or dict"""
        if isinstance(json_data, str):
            self.data = json.loads(json_data)
        else:
            self.data = json_data
            
        # Convert to DataFrame for easier analysis
        self.df = pd.json_normalize(self.data)
        
        # Categorize items based on filename or content
        self._categorize_items()
        
        print(f"Loaded {len(self.data)} items: {len(self.threat_items)} potential threats, {len(self.safe_items)} safe items")
        return self.df
    
    def _categorize_items(self):
        """Categorize items as threat or safe based on path or content"""
        for idx, item in enumerate(self.data):
            if '_threat' in item['path'].lower() or 'threat' in str(item.get('content', '')).lower():
                self.threat_items.append(idx)
            elif '_safe' in item['path'].lower():
                self.safe_items.append(idx)
            # Look for threat-related keywords in content
            elif item.get('content') and any(keyword in str(item['content']).lower() for keyword in 
                                            ['bomb', 'attack', 'explosive', 'threat', 'terrorist']):
                self.threat_items.append(idx)
            # Check for weapons in tags
            elif any(weapon in str(item.get('tags', [])).lower() for weapon in 
                    ['assault rifle', 'rifle', 'revolver', 'weapon', 'bulletproof']):
                self.threat_items.append(idx)
            else:
                self.safe_items.append(idx)
    
    def analyze_threats(self):
        """Analyze threat-related items"""
        threat_analysis = {
            'count': len(self.threat_items),
            'types': Counter(),
            'tags': Counter(),
            'files': []
        }
        
        for idx in self.threat_items:
            item = self.data[idx]
            threat_analysis['types'][item['type']] += 1
            
            for tag in item.get('tags', []):
                threat_analysis['tags'][tag] += 1
                
            threat_analysis['files'].append({
                'path': item['path'],
                'type': item['type'],
                'tags': item.get('tags', [])
            })
            
        return threat_analysis
    
    def find_tag_correlations(self):
        """Find correlations between items based on shared tags"""
        tag_to_files = defaultdict(list)
        file_to_tags = defaultdict(list)
        
        # Map tags to files and vice versa
        for idx, item in enumerate(self.data):
            file_path = item['path']
            for tag in item.get('tags', []):
                tag_to_files[tag].append(file_path)
                file_to_tags[file_path].append(tag)
        
        # Find files that share tags
        shared_tags = {}
        for tag, files in tag_to_files.items():
            if len(files) > 1:  # Multiple files share this tag
                shared_tags[tag] = files
        
        # Find co-occurring tags
        tag_cooccurrence = defaultdict(int)
        for file_path, tags in file_to_tags.items():
            if len(tags) > 1:
                for i in range(len(tags)):
                    for j in range(i+1, len(tags)):
                        tag_pair = tuple(sorted([tags[i], tags[j]]))
                        tag_cooccurrence[tag_pair] += 1
        
        # Store results
        self.correlations['shared_tags'] = shared_tags
        self.correlations['tag_cooccurrence'] = dict(tag_cooccurrence)
        
        return shared_tags, dict(tag_cooccurrence)
    
    def build_tag_graph(self):
        """Build a network graph of tags and files"""
        G = nx.Graph()
        
        # Add file nodes
        for idx, item in enumerate(self.data):
            file_path = item['path']
            is_threat = idx in self.threat_items
            G.add_node(file_path, type='file', file_type=item['type'], 
                      is_threat=is_threat)
            
            # Add tag nodes and connections
            for tag in item.get('tags', []):
                if tag not in G:
                    G.add_node(tag, type='tag')
                G.add_edge(file_path, tag)
        
        self.tag_graph = G
        
        # Calculate basic metrics
        centrality = nx.degree_centrality(G)
        communities = list(nx.community.greedy_modularity_communities(G))
        
        graph_stats = {
            'nodes': G.number_of_nodes(),
            'edges': G.number_of_edges(),
            'top_central_nodes': sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5],
            'communities': len(communities),
            'largest_community_size': len(communities[0]) if communities else 0
        }
        
        return G, graph_stats
    
    def analyze_content(self):
        """Analyze text content for correlations and keywords"""
        # Extract content from text files
        text_contents = []
        
        for item in self.data:
            if item['type'] == 'file' and item.get('content'):
                text_contents.append({
                    'path': item['path'],
                    'content': item['content'],
                    'is_threat': any(item['path'] == self.data[idx]['path'] for idx in self.threat_items)
                })
        
        # Look for common phrases and keywords
        threat_keywords = ['bomb', 'attack', 'threat', 'explosive', 'rifle', 'planning', 'illegal']
        keyword_occurrences = defaultdict(list)
        
        for item in text_contents:
            content = item['content'].lower()
            for keyword in threat_keywords:
                if keyword in content:
                    keyword_occurrences[keyword].append(item['path'])
        
        # Cross-reference content between files
        content_similarity = []
        for i in range(len(text_contents)):
            for j in range(i+1, len(text_contents)):
                item1 = text_contents[i]
                item2 = text_contents[j]
                
                # Use basic word overlap as similarity measure
                words1 = set(re.findall(r'\b\w+\b', item1['content'].lower()))
                words2 = set(re.findall(r'\b\w+\b', item2['content'].lower()))
                
                if words1 and words2:  # Ensure non-empty sets
                    overlap = len(words1.intersection(words2))
                    similarity = overlap / len(words1.union(words2))
                    
                    if similarity > 0.1:  # Only record significant similarities
                        content_similarity.append({
                            'file1': item1['path'],
                            'file2': item2['path'],
                            'similarity': similarity,
                            'common_words': words1.intersection(words2)
                        })
        
        return {
            'keyword_occurrences': dict(keyword_occurrences),
            'content_similarity': content_similarity
        }
    
    def extract_date_patterns(self):
        """Extract dates from filenames and analyze patterns"""
        date_pattern = re.compile(r'(\d{4}-\d{2}-\d{2})')
        file_dates = {}
        
        for item in self.data:
            matches = date_pattern.findall(item['path'])
            if matches:
                try:
                    file_date = datetime.strptime(matches[0], '%Y-%m-%d')
                    file_dates[item['path']] = file_date
                except ValueError:
                    continue
        
        # Group files by date
        date_groups = defaultdict(list)
        for file_path, date in file_dates.items():
            date_str = date.strftime('%Y-%m-%d')
            date_groups[date_str].append(file_path)
        
        return dict(date_groups)
    
    def generate_threat_report(self):
        """Generate a comprehensive threat report based on all analyses"""
        # Run all analyses if not done already
        if not self.correlations:
            self.find_tag_correlations()
        
        if not self.tag_graph:
            self.build_tag_graph()
        
        content_analysis = self.analyze_content()
        date_patterns = self.extract_date_patterns()
        threat_analysis = self.analyze_threats()
        
        # Identify key threat indicators
        weapon_related_tags = [tag for tag, count in threat_analysis['tags'].items() 
                             if any(w in tag.lower() for w in ['rifle', 'revolver', 'mask', 'bulletproof'])]
        
        # Identify related files based on tag connections
        related_files = []
        for tag in weapon_related_tags:
            if tag in self.correlations['shared_tags']:
                related_files.extend(self.correlations['shared_tags'][tag])
        
        # Remove duplicates
        related_files = list(set(related_files))
        
        # Get content similarities between threat files
        threat_paths = [self.data[idx]['path'] for idx in self.threat_items]
        threat_similarities = [sim for sim in content_analysis['content_similarity'] 
                              if sim['file1'] in threat_paths or sim['file2'] in threat_paths]
        
        report = {
            'summary': {
                'total_items': len(self.data),
                'threat_items': len(self.threat_items),
                'weapon_related_items': sum(1 for item in self.data if any(tag in weapon_related_tags for tag in item.get('tags', [])))
            },
            'key_threats': {
                'weapon_related_tags': weapon_related_tags,
                'related_files': related_files,
                'key_content_keywords': content_analysis['keyword_occurrences']
            },
            'connections': {
                'tag_connections': self.correlations['tag_cooccurrence'],
                'content_similarities': threat_similarities
            },
            'timeline': date_patterns
        }
        
        return report
    
    def visualize_tag_network(self, filename='tag_network.png'):
        """Visualize the tag network as an image"""
        if not self.tag_graph:
            self.build_tag_graph()
            
        G = self.tag_graph
        
        # Create color mapping
        colors = []
        for node in G.nodes():
            if G.nodes[node].get('type') == 'tag':
                colors.append('lightblue')
            elif G.nodes[node].get('is_threat', False):
                colors.append('red')
            else:
                colors.append('green')
        
        # Set node sizes
        sizes = []
        for node in G.nodes():
            if G.nodes[node].get('type') == 'tag':
                sizes.append(100)
            else:
                sizes.append(50)
        
        plt.figure(figsize=(12, 10))
        pos = nx.spring_layout(G, seed=42)
        nx.draw_networkx(G, pos, node_color=colors, node_size=sizes, 
                        with_labels=True, font_size=8, alpha=0.7)
        plt.title("File and Tag Network (Red=Threat Files, Green=Safe Files, Blue=Tags)")
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(filename)
        print(f"Network visualization saved as {filename}")
        return filename

def process_metadata(data):
    """Process metadata JSON and return comprehensive analysis"""
    analyzer = ForensicMetadataAnalyzer()
    analyzer.load_json_data(data)
    
    # Run all analyses
    tag_correlations = analyzer.find_tag_correlations()
    network_analysis = analyzer.build_tag_graph()
    content_analysis = analyzer.analyze_content()
    threat_report = analyzer.generate_threat_report()
    
    # Generate visualization
    viz_file = analyzer.visualize_tag_network()
    
    return {
        'threat_report': threat_report,
        'tag_correlations': tag_correlations,
        'content_analysis': content_analysis,
        'network_stats': network_analysis[1]
    }

# Example usage
if __name__ == "__main__":
    # This would be replaced by actual data loading in your web app
    with open('testing/yash.json', 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    
    results = process_metadata(metadata)
    print(json.dumps(results, indent=2))