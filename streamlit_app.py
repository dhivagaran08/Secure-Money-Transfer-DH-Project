import streamlit as st
import requests, json
from utils.crypto_utils import generate_dh_params, dh_generate_private_key, dh_compute_public, dh_compute_shared, derive_aes_key, aes_gcm_encrypt, aes_gcm_decrypt

SERVER = 'http://127.0.0.1:5000'

st.title('Secure Money Transfer (DH Demo)')

st.info('This is a demo. The server stores only public keys and ciphertexts. Do not use in production as-is.')

user_id = st.text_input('Your user id', value='alice')
if 'priv' not in st.session_state:
    st.session_state.priv = None
    st.session_state.pub = None

col1, col2 = st.columns(2)
with col1:
    if st.button('Generate & Register DH Key'):
        p, g = generate_dh_params()
        priv = dh_generate_private_key(p)
        pub = dh_compute_public(g, priv, p)
        st.session_state.priv = priv
        st.session_state.pub = pub
        resp = requests.post(f"{SERVER}/register_key", json={'user_id': user_id, 'p': str(p), 'g': str(g), 'pub': str(pub)})
        st.success(f"Registered key for {user_id}: {resp.json()}")
with col2:
    if st.button('Show My Public Key'):
        if st.session_state.pub is None:
            st.warning('No key generated yet')
        else:
            st.code(str(st.session_state.pub))

st.markdown('---')

recipient = st.text_input('Recipient id', value='bob')
amount = st.number_input('Amount', min_value=1, value=100)
if st.button('Send Encrypted Transaction'):
    # fetch recipient public key
    resp = requests.get(f"{SERVER}/get_key/{recipient}")
    if resp.status_code != 200:
        st.error('Recipient key not found. Make sure recipient registered.')
    else:
        rec = resp.json()
        rec_pub = int(rec['pub'])
        rec_p = int(rec['p'])
        if st.session_state.priv is None:
            st.error('Generate your key first')
        else:
            shared = dh_compute_shared(rec_pub, st.session_state.priv, rec_p)
            aes_key = derive_aes_key(shared)
            transaction = {'from': user_id, 'to': recipient, 'amount': int(amount), 'timestamp': '2025-11-14'}
            pt = json.dumps(transaction).encode()
            enc = aes_gcm_encrypt(aes_key, pt)
            send_payload = {'to': recipient, 'from': user_id, 'iv': enc['iv'].hex(), 'ct': enc['ct'].hex(), 'tag': enc['tag'].hex(), 'aad': ''}
            r = requests.post(f"{SERVER}/send_transaction", json=send_payload)
            st.success(f"Sent: {r.json()}")

st.markdown('---')
if st.button('Fetch My Inbox'):
    r = requests.get(f"{SERVER}/inbox/{user_id}")
    if r.status_code != 200:
        st.error('Could not fetch inbox')
    else:
        msgs = r.json().get('messages', [])
        if not msgs:
            st.info('No messages')
        else:
            for m in msgs:
                st.write('From:', m['from'])
                if st.session_state.priv is None:
                    st.warning('No private key to decrypt')
                    continue
                # fetch sender public to compute shared
                rec = requests.get(f"{SERVER}/get_key/{m['from']}").json()
                sender_pub = int(rec['pub'])
                p = int(rec['p'])
                shared = dh_compute_shared(sender_pub, st.session_state.priv, p)
                aes_key = derive_aes_key(shared)
                try:
                    pt = aes_gcm_decrypt(aes_key, bytes.fromhex(m['iv']), bytes.fromhex(m['ct']), bytes.fromhex(m['tag']))
                    st.success('Decrypted: ' + pt.decode())
                except Exception as e:
                    st.error('Decryption failed: ' + str(e))
