import webview
import sys

def start_app():
    # URL do seu frontend LINDO na Vercel
    url = "https://sentinel360-cyber.vercel.app/"
    
    # Criar a janela
    window = webview.create_window(
        'Sentinel 360 - Cyber Defense', 
        url,
        width=1280, 
        height=800,
        resizable=True,
        background_color='#000000'
    )
    
    # gui='edgehtml' garante que ele use o motor moderno do Edge no Windows
    webview.start(gui='edgehtml')

if __name__ == "__main__":
    start_app()