import base64, hashlib, os, zipfile
from urllib.parse import quote
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509 as cx509
BASE = os.path.dirname(os.path.abspath(__file__))
WDIR = os.path.join(BASE, 'tpk'); OUT = os.path.join(BASE, 'tvroot.tpk')
DSN = 'http://www.w3.org/2000/09/xmldsig#'
def q(t): return '{%s}%s' % (DSN, t)
files = {}
for root, _, names in os.walk(WDIR):
    for n in names:
        p = os.path.join(root, n)
        files[os.path.relpath(p, WDIR)] = open(p, 'rb').read()
author_key = serialization.load_pem_private_key(open(BASE+'/tpkauthor.key','rb').read(), None)
author_cert = cx509.load_pem_x509_certificate(open(BASE+'/tpkauthor.crt','rb').read())
ca_cert = cx509.load_pem_x509_certificate(open(BASE+'/certificate-generator_0.1.4/data/tools/certificate-generator/certificates/developer/tizen-developer-ca.cer','rb').read())
dkey, dcert, dchain = pkcs12.load_key_and_certificates(open(BASE+'/tizen-distributor-signer.p12','rb').read(), b'tizenpkcs12passfordsigner')
def b64cert(c): return base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
def dig(b): return base64.b64encode(hashlib.sha512(b).digest()).decode()
def make_sig(sig_id, role, key, certs, refs):
    root = etree.Element(q('Signature'), Id=sig_id, nsmap={None: DSN})
    si = etree.SubElement(root, q('SignedInfo'))
    etree.SubElement(si, q('CanonicalizationMethod'), Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')
    etree.SubElement(si, q('SignatureMethod'), Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha512')
    for uri, data in refs:
        r = etree.SubElement(si, q('Reference'), URI=uri)
        etree.SubElement(r, q('DigestMethod'), Algorithm='http://www.w3.org/2001/04/xmlenc#sha512')
        dv = etree.SubElement(r, q('DigestValue')); dv.text = dig(data)
    sv = etree.SubElement(root, q('SignatureValue'))
    ki = etree.SubElement(root, q('KeyInfo')); xd = etree.SubElement(ki, q('X509Data'))
    for c in certs:
        xe = etree.SubElement(xd, q('X509Certificate')); xe.text = b64cert(c)
    obj = etree.SubElement(root, q('Object'), Id='prop')
    sps = etree.SubElement(obj, q('SignatureProperties'), nsmap={'dsp': 'http://www.w3.org/2009/xmldsig-properties'})
    DSP = '{http://www.w3.org/2009/xmldsig-properties}'
    for pid, elem, uri in (('profile','Profile','http://www.w3.org/ns/widgets-digsig#profile'),
                           ('role','Role','http://www.w3.org/ns/widgets-digsig#role-'+role)):
        sp = etree.SubElement(sps, q('SignatureProperty'), Id=pid, Target='#'+sig_id)
        etree.SubElement(sp, DSP+elem, URI=uri)
    sp3 = etree.SubElement(sps, q('SignatureProperty'), Id='identifier', Target='#'+sig_id)
    etree.SubElement(sp3, DSP+'Identifier')
    sig = key.sign(etree.tostring(si, method='c14n', exclusive=True), padding.PKCS1v15(), hashes.SHA512())
    sv.text = base64.b64encode(sig).decode()
    return etree.tostring(root, xml_declaration=True, encoding='UTF-8')
sorted_files = sorted(files)
author_refs = [(quote(p, safe=''), files[p]) for p in sorted_files]
author_sig = make_sig('AuthorSignature', 'author', author_key, [author_cert, ca_cert], author_refs)
dist_sig = make_sig('DistributorSignature', 'distributor', dkey, [dcert] + list(dchain or []), [('author-signature.xml', author_sig)] + author_refs)
with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
    for p in sorted_files: z.writestr(p, files[p])
    z.writestr('author-signature.xml', author_sig)
    z.writestr('signature1.xml', dist_sig)
print('built', OUT, os.path.getsize(OUT), 'bytes; author:', author_cert.subject.rfc4514_string())
