# GRUPO: NICOLAS KEISMANAS - 23013693 e GUSTAVO TOLEDO - 21011066
# credencias pré-cadastradas: alice@puc.com / bob@puc.com


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

# Conexão Mongo
uri = "mongodb+srv://nkeismanas11:nature03@cluster0.beowa.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    print("Conexão bem-sucedida com o MongoDB!")
except Exception as e:
    print(e)

db = client['chat_database']
credential_collection = db['credential']
messages_collection = db['messages']  # Coleção de mensagens

# Função para derivar a chave a partir de uma senha e um salt
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Tamanho da chave de 256 bits (32 bytes)
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

# Função para criptografar a mensagem (cypher)
def cypher(message, key):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

# Função para descriptografar a mensagem (decrypt)
def decrypt(encrypted_message, key):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

# Função para enviar mensagem criptografada pro banco
def send_message_to_db(sender, recipient, message, password):
    salt = os.urandom(16)  # Gerar um salt aleatório
    key = derive_key_from_password(password, salt)  # Derivar a chave usando a senha e o salt
    encrypted_message = cypher(message, key)

    message_document = {
        'from': sender,
        'to': recipient,
        'message': encrypted_message,
        'salt': urlsafe_b64encode(salt).decode('utf-8')  # Salvar o salt junto com a mensagem
    }
    messages_collection.insert_one(message_document)
    print(f"Mensagem de {sender} para {recipient} enviada e criptografada com sucesso!")
    print("--------------------------------------------------------------------------------")

# Função para verificar e mostrar mensagens recebidas
def check_received_messages(user_email, password):
    messages = messages_collection.find({'to': user_email})
    messages_found = False

    for msg in messages:
        messages_found = True
        print(f"Você tem uma mensagem de {msg['from']}.")
        show_message = input("Você gostaria de ver a mensagem? (sim/não): ").strip().lower()

        if show_message == 'sim':
            print(f"Mensagem criptografada: {msg['message']}")

            salt = urlsafe_b64decode(msg['salt'])

            key = derive_key_from_password(password, salt)

            decrypted_message = decrypt(msg['message'], key)
            print(f"Mensagem descriptografada: {decrypted_message}")

    if not messages_found:
        print("Nenhuma nova mensagem recebida.")

    # Pergunta se usuário quer enviar uma mensagem depois de ver as mensagens recebidas
    send_new_message = input("Você gostaria de enviar uma nova mensagem? (sim/não): ").strip().lower()
    if send_new_message == 'sim':
        return True
    else:
        return False

# Função realizar login
def login():
    while True:
        email = input("Digite seu e-mail: ")
        password = input("Digite sua senha: ")

        user = credential_collection.find_one({'email': email, 'password': password})

        if user:
            print("Login bem-sucedido!")
            return email, password  # Retorna o e-mail do usuário e a senha
        else:
            print("E-mail ou senha incorretos. Tente novamente.")

# Função enviar nova mensagem
def chat(user_email, password):
    sender = user_email
    recipient = input("Digite o e-mail do destinatário: ")
    message = input("Digite a mensagem: ")

    send_message_to_db(sender, recipient, message, password)

# Main function
if __name__ == "__main__":
    while True:
        user_email, password = login()  # Tenta login até ser bem sucedido

        # Verifica se o usuário tem mensagens recebidas e oferecer para ler
        should_send_message = check_received_messages(user_email, password)

        if should_send_message:
            chat(user_email, password)
        else:
            print("Encerrando o programa.")
            break
