import os
import csv

def export_to_csv(data, filename="relatorio_final_sentinel.csv"):
    """Salva os resultados encontrados em um arquivo CSV[cite: 19]."""
    if not data:
        return False
    
    with open(filename, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys(), delimiter=';')
        writer.writeheader()
        writer.writerows(data)
    return True

def delete_files(file_list):
    """Remove fisicamente os arquivos da lista fornecida."""
    sucesso = 0
    erro = 0
    for item in file_list:
        try:
            os.remove(item['caminho'])
            sucesso += 1
        except Exception as e:
            print(f"  [!] Falha ao remover {item['nome']}: {e}")
            erro += 1
    return sucesso, erro