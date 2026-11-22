import base64, hashlib, os, zipfile
from urllib.parse import quote
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509 as cx509
BASE = os.path.dirname(os.path.abspath(__file__)); WDIR = os.path.join(BASE, 'wgtvar'); OUT = os.path.join(BASE, 'wgtvar.wgt')
DSN = 'http://www.w3.org/2000/09/xmldsig#'
def q(t): return '{%s}%s' % (DSN, t)
files = {}
for root, _, names in os.walk(WDIR):
    for n in names:
        p = os.path.join(root, n); files[os.path.relpath(p, WDIR)] = open(p, 'rb').read()
akey = serialization.load_pem_private_key(open(BASE+'/tpkauthor.key','rb').read(), None)
acert = cx509.load_pem_x509_certificate(open(BASE+'/reisauthor.crt','rb').read())
ca = cx509.load_pem_x509_certificate(open(BASE+'/certificate-generator_0.1.4/data/tools/certificate-generator/certificates/developer/tizen-developer-ca.cer','rb').read())
dkey, dcert, dchain = pkcs12.load_key_and_certificates(open(BASE+'/tizen-distributor-signer.p12','rb').read(), b'tizenpkcs12passfordsigner')
def b64(c): return base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
def dig(b): return base64.b64encode(hashlib.sha512(b).digest()).decode()
def sig(sid, role, key, certs, refs):
    r_ = etree.Element(q('Signature'), Id=sid, nsmap={None: DSN})
    si = etree.SubElement(r_, q('SignedInfo'))
    etree.SubElement(si, q('CanonicalizationMethod'), Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')
    etree.SubElement(si, q('SignatureMethod'), Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha512')
    for uri, d in refs:
        r = etree.SubElement(si, q('Reference'), URI=uri)
        etree.SubElement(r, q('DigestMethod'), Algorithm='http://www.w3.org/2001/04/xmlenc#sha512')
        dv = etree.SubElement(r, q('DigestValue')); dv.text = dig(d)
    sv = etree.SubElement(r_, q('SignatureValue'))
    ki = etree.SubElement(r_, q('KeyInfo')); xd = etree.SubElement(ki, q('X509Data'))
    for c in certs:
        xe = etree.SubElement(xd, q('X509Certificate')); xe.text = b64(c)
    obj = etree.SubElement(r_, q('Object'), Id='prop')
    sps = etree.SubElement(obj, q('SignatureProperties'), nsmap={'dsp': 'http://www.w3.org/2009/xmldsig-properties'})
    DSP = '{http://www.w3.org/2009/xmldsig-properties}'
    for pid, elem, uri in (('profile','Profile','http://www.w3.org/ns/widgets-digsig#profile'), ('role','Role','http://www.w3.org/ns/widgets-digsig#role-'+role)):
        sp = etree.SubElement(sps, q('SignatureProperty'), Id=pid, Target='#'+sid); etree.SubElement(sp, DSP+elem, URI=uri)
    sp3 = etree.SubElement(sps, q('SignatureProperty'), Id='identifier', Target='#'+sid); etree.SubElement(sp3, DSP+'Identifier')
    sv.text = base64.b64encode(key.sign(etree.tostring(si, method='c14n', exclusive=True), padding.PKCS1v15(), hashes.SHA512())).decode()
    return etree.tostring(r_, xml_declaration=True, encoding='UTF-8')
sf = sorted(files); arefs = [(quote(p, safe=''), files[p]) for p in sf]
asig = sig('AuthorSignature', 'author', akey, [acert, ca], arefs)
dsig = sig('DistributorSignature', 'distributor', dkey, [dcert] + list(dchain or []), [('author-signature.xml', asig)] + arefs)
with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
    for p in sf: z.writestr(p, files[p])
    z.writestr('author-signature.xml', asig); z.writestr('signature1.xml', dsig)
print('built wgtvar.wgt', os.path.getsize(OUT))
