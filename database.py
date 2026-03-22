import os
import certifi
from pymongo import MongoClient
from datetime import datetime

MONGO_URI = os.environ.get("MONGO_URI")

try:
    # Conexão com suporte a SSL via certifi (essencial para AWS/Atlas)
    client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
    db = client["sentinel360"]
    collection = db["scan_results"]
    logs_collection = db["activity_logs"] # Para auditoria futura
    
    # Teste de conexão
    client.admin.command('ping')
    print("[DB] Conectado com sucesso ao MongoDB na AWS.")
except Exception as e:
    print(f"[ERRO DB] Falha ao conectar: {e}")

def save_scan_results(results):
    """
    Limpa os resultados anteriores e salva o novo scan.
    Adiciona um timestamp para controle de histórico.
    """
    if not results:
        return False
    
    try:
        # Adiciona a data do scan em cada documento
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for item in results:
            item["last_scan"] = scan_date
            
        # Opcional: Limpar scan anterior para manter o dashboard sempre com o último estado
        # Se quiser manter histórico, comente a linha abaixo
        collection.delete_many({}) 
        
        # Insere os novos dados
        collection.insert_many(results)
        return True
    except Exception as e:
        print(f"[ERRO DB] Falha ao salvar resultados: {e}")
        return False

def get_all_results():
    """
    Recupera todos os itens para o Frontend.
    O campo _id do Mongo é removido para evitar erro de serialização JSON.
    """
    try:
        return list(collection.find({}, {"_id": 0}))
    except Exception as e:
        print(f"[ERRO DB] Falha ao buscar dados: {e}")
        return []

def delete_specific_file(path):
    """
    Remove o registro do banco de dados após a exclusão física do arquivo.
    """
    try:
        result = collection.delete_one({"caminho": path})
        
        # Registra a ação no log de auditoria (Cyber Defense Standard)
        logs_collection.insert_one({
            "acao": "REMOÇÃO",
            "caminho": path,
            "data": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "SUCESSO" if result.deleted_count > 0 else "NÃO ENCONTRADO"
        })
        return result.deleted_count > 0
    except Exception as e:
        print(f"[ERRO DB] Falha ao remover item: {e}")
        return False