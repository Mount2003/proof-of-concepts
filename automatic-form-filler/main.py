import pymupdf

doc = pymupdf.open("table.pdf")
for page in doc:
    print(page.get_text())
    