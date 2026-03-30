import os
from dotenv import load_dotenv
import google.genai as genai

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL")

if not API_KEY:
    raise ValueError(" GEMINI_API_KEY non trouvé dans .env !")
client = genai.Client(api_key=API_KEY)

print("💬 Chat avec Gemini (tape 'exit' pour quitter)")

while True:
    msg = input("Toi: ")
    if msg.strip().lower() == "exit":
        break
    if not msg.strip():
        continue 
    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=[msg] 
        )
        generated_text = response.textbo
        print("Bot:", generated_text)

    except Exception as e:
        print("⚠️ Erreur API :", str(e))