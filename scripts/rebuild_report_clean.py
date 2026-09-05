from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import xml.etree.ElementTree as ET

from complete_report import build_body, tag, W

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "Group7_FinalReport_COMPLETED.docx"
NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
ET.register_namespace("w", W)
ET.register_namespace("r", NS_R)


def xml_root(name):
    return ET.Element(name)


def styles_xml():
    root = ET.Element(f"{{{W}}}styles")
    def style(style_id, name, based=None, size=24, bold=False):
        s = ET.SubElement(root, f"{{{W}}}style", {f"{{{W}}}type": "paragraph", f"{{{W}}}styleId": style_id})
        ET.SubElement(s, f"{{{W}}}name", {f"{{{W}}}val": name})
        if based: ET.SubElement(s, f"{{{W}}}basedOn", {f"{{{W}}}val": based})
        rpr = ET.SubElement(s, f"{{{W}}}rPr")
        ET.SubElement(rpr, f"{{{W}}}rFonts", {f"{{{W}}}ascii": "Arial", f"{{{W}}}hAnsi": "Arial", f"{{{W}}}eastAsia": "Arial"})
        ET.SubElement(rpr, f"{{{W}}}sz", {f"{{{W}}}val": str(size)})
        if bold: ET.SubElement(rpr, f"{{{W}}}b")
    style("Normal", "Normal", size=23)
    style("Heading1", "heading 1", "Normal", 28, True)
    style("Heading2", "heading 2", "Normal", 25, True)
    style("ListBullet", "List Bullet", "Normal", 23)
    style("TableGrid", "Table Grid", "Normal", 20)
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def document_xml():
    root = ET.Element(f"{{{W}}}document")
    body = ET.Element(f"{{{W}}}body")
    dummy = ET.Element(f"{{{W}}}body")
    sect = ET.SubElement(dummy, f"{{{W}}}sectPr")
    ET.SubElement(sect, f"{{{W}}}pgSz", {f"{{{W}}}w": "11906", f"{{{W}}}h": "16838"})
    ET.SubElement(sect, f"{{{W}}}pgMar", {f"{{{W}}}top": "1440", f"{{{W}}}right": "1440", f"{{{W}}}bottom": "1440", f"{{{W}}}left": "1440"})
    generated = build_body(dummy)
    for node in generated.iter():
        if node.tag == f"{{{W}}}pStyle" and node.get(f"{{{W}}}val") == "List Bullet":
            node.set(f"{{{W}}}val", "ListBullet")
        if node.tag == f"{{{W}}}tblStyle" and node.get(f"{{{W}}}val") == "Table Grid":
            node.set(f"{{{W}}}val", "TableGrid")
    for child in list(generated): body.append(child)
    root.append(body)
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


CONTENT_TYPES = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>'''.encode()
ROOT_RELS = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'''.encode()
DOC_RELS = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''.encode()


with ZipFile(OUT, "w", ZIP_DEFLATED) as z:
    z.writestr("[Content_Types].xml", CONTENT_TYPES)
    z.writestr("_rels/.rels", ROOT_RELS)
    z.writestr("word/_rels/document.xml.rels", DOC_RELS)
    z.writestr("word/document.xml", document_xml())
    z.writestr("word/styles.xml", styles_xml())
print(f"created {OUT}")
