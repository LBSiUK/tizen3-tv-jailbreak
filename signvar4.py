import base64, hashlib, os, re, zipfile
from urllib.parse import quote
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509 as cx509
BASE = os.path.dirname(os.path.abspath(__file__))
def wrap76(b64): return '\n'.join(b64[i:i+76] for i in range(0, len(b64), 76))
def make_sig(sid, role, key, certs, refs):
    L = ['<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="%s">' % sid]
    L.append('<SignedInfo>')
    L.append('<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>')
    L.append('<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"></SignatureMethod>')
    for uri, data in refs:
        L.append('<Reference URI="%s">' % uri)
        L.append('<Transforms><Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"></Transform></Transforms>')
        L.append('<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"></DigestMethod>')
        dv = base64.b64encode(hashlib.sha512(data).digest()).decode()
        L.append('<DigestValue>%s</DigestValue>' % wrap76(dv))
        L.append('</Reference>')
    si_xml = ('\n'.join(L)).encode()
    c14n = etree.tostring(etree.fromstring(si_xml), method='c14n', exclusive=True)
    sig = base64.b64encode(key.sign(c14n, padding.PKCS1v15(), hashes.SHA512())).decode()
    L.append('</SignedInfo>')
    L.append('<SignatureValue>%s</SignatureValue>' % wrap76(sig))
    L.append('<KeyInfo><X509Data>')
    for c in certs:
        L.append('<X509Certificate>%s</X509Certificate>' % wrap76(base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()))
    L.append('</X509Data></KeyInfo>')
    L.append('<Object Id="prop"><SignatureProperties xmlns:dsp="http://www.w3.org/2009/xmldsig-properties"><SignatureProperty Id="profile" Target="#%s"><dsp:Profile URI="http://www.w3.org/ns/widgets-digsig#profile"></dsp:Profile></SignatureProperty><SignatureProperty Id="role" Target="#%s"><dsp:Role URI="http://www.w3.org/ns/widgets-digsig#role-%s"></dsp:Role></SignatureProperty><SignatureProperty Id="identifier" Target="#%s"><dsp:Identifier></dsp:Identifier></SignatureProperty></SignatureProperties></Object>' % (sid, sid, role, sid))
    L.append('</Signature>')
    return ('\n'.join(L)).encode()
def build(wdir, out, pkg_files=None):
    files = {}
    for root, _, names in os.walk(wdir):
        for n in names:
            p = os.path.join(root, n)
            rel = os.path.relpath(p, wdir)
            if rel in ('author-signature.xml', 'signature1.xml'): continue
            files[rel] = open(p, 'rb').read()
    akey = serialization.load_pem_private_key(open(BASE+'/tpkauthor.key','rb').read(), None)
    acert = cx509.load_pem_x509_certificate(open(BASE+'/tpkauthor.crt','rb').read())
    ca = cx509.load_pem_x509_certificate(open(BASE+'/certificate-generator_0.1.4/data/tools/certificate-generator/certificates/developer/tizen-developer-ca.cer','rb').read())
    dkey, dcert, dchain = pkcs12.load_key_and_certificates(open(BASE+'/tizen-distributor-signer.p12','rb').read(), b'tizenpkcs12passfordsigner')
    sf = sorted(files)
    arefs = [(quote(p, safe=''), files[p]) for p in sf]
    asig = make_sig('AuthorSignature', 'author', akey, [acert, ca], arefs)
    dsig = make_sig('DistributorSignature', 'distributor', dkey, [dcert] + list(dchain or []), [('author-signature.xml', asig)] + arefs)
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('author-signature.xml', asig)
        for p in sf: z.writestr(p, files[p])
        z.writestr('signature1.xml', dsig)
    print('built', out, os.path.getsize(out))
build(os.path.join(BASE, 'wgtvar'), os.path.join(BASE, 'wgtvar.wgt'))
