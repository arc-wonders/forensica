from PIL import Image
import pytesseract

# Set the path to tesseract if needed
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

img = Image.open('C:\Users\Arkin Kansra\OneDrive\Desktop\Forensica\devices\test\h.jpg')  # Replace with your image
text = pytesseract.image_to_string(img)
print(text)