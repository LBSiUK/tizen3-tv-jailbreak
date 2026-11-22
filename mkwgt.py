import base64, hashlib, os, subprocess, zipfile
from urllib.parse import quote
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509 as cx509

BASE = os.path.dirname(os.path.abspath(__file__))
WDIR = os.path.join(BASE, 'wgt')
OUT = os.path.join(BASE, 'tvroot.wgt')
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
    ki = etree.SubElement(root, q('KeyInfo'))
    xd = etree.SubElement(ki, q('X509Data'))
    for c in certs:
        xe = etree.SubElement(xd, q('X509Certificate')); xe.text = b64cert(c)
    obj = etree.SubElement(root, q('Object'), Id='prop')
    sps = etree.SubElement(obj, q('SignatureProperties'), nsmap={'dsp': 'http://www.w3.org/2009/xmldsig-properties'})
    DSP = '{http://www.w3.org/2009/xmldsig-properties}'
    sp1 = etree.SubElement(sps, q('SignatureProperty'), Id='profile', Target='#'+sig_id)
    etree.SubElement(sp1, DSP+'Profile', URI='http://www.w3.org/ns/widgets-digsig#profile')
    sp2 = etree.SubElement(sps, q('SignatureProperty'), Id='role', Target='#'+sig_id)
    etree.SubElement(sp2, DSP+'Role', URI='http://www.w3.org/ns/widgets-digsig#role-'+role)
    sp3 = etree.SubElement(sps, q('SignatureProperty'), Id='identifier', Target='#'+sig_id)
    etree.SubElement(sp3, DSP+'Identifier')
    sig = key.sign(etree.tostring(si, method='c14n', exclusive=True), padding.PKCS1v15(), hashes.SHA512())
    sv.text = base64.b64encode(sig).decode()
    return etree.tostring(root, xml_declaration=True, encoding='UTF-8')
sorted_files = sorted(files)
author_refs = [(quote(p, safe=''), files[p]) for p in sorted_files]
author_sig = make_sig('AuthorSignature', 'author', author_key, [author_cert, ca_cert], author_refs)
entries = [(p, files[p]) for p in sorted_files] + [('author-signature.xml', author_sig)]
dp12 = os.path.join(BASE, 'tizen-distributor-signer.p12')
pw = os.environ.get('P12PW', 'tizenpkcs12passfingerprint')
try:
    dkey, dcert, dchain = pkcs12.load_key_and_certificates(open(dp12,'rb').read(), pw.encode())
    dist_sig = make_sig('DistributorSignature', 'distributor', dkey, [dcert] + list(dchain or []),
                        [('author-signature.xml', author_sig)] + author_refs)
    entries.append(('signature1.xml', dist_sig))
    print('distributor sig added, CN:', dcert.subject.rfc4514_string())
except Exception as e:
    print('NO distributor sig (%s) — author-only build' % e.__class__.__name__)
with zipfile.ZipFile(OUT, 'w', zipfile.ZIP_DEFLATED) as z:
    for name, data in entries: z.writestr(name, data)
print('built', OUT, os.path.getsize(OUT), 'bytes,', len(entries), 'entries')
