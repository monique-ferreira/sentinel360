import scanner_engine
import actions_manager
import sys

def main():
    print("="*50)
    print("        SENTINEL 360 - CYBER DEFENSE")
    print("="*50)
    
    try:
        dias_input = input("Dias para considerar inatividade (padrão 180): ")
        dias = int(dias_input) if dias_input.strip() else 180
        
        print(f"\n[1/3] Iniciando Varredura... (Limite: {dias} dias)")
        resultados = scanner_engine.run_full_scan(dias)
        
        if not resultados:
            print("\n[OK] Nenhum arquivo de risco ou inativo encontrado.")
            return

        print(f"[2/3] Varredura Concluída. {len(resultados)} itens identificados.")
        
        # Salva o relatório automaticamente
        actions_manager.export_to_csv(resultados)
        print("[INFO] Relatório gerado: relatorio_final_sentinel.csv")

        # Menu de Ação Humana
        print("\n" + "-"*30)
        print("MENU DE REMEDIAÇÃO:")
        print("1. Listar caminhos encontrados")
        print("2. Remover APENAS arquivos com Credenciais/Riscos")
        print("3. Remover TUDO (Inativos e Riscos)")
        print("4. Sair (Manter arquivos)")
        
        escolha = input("\nSelecione uma opção: ")

        if escolha == "1":
            for i, r in enumerate(resultados):
                print(f"[{i}] {r['riscos']} | {r['caminho']}")
        
        elif escolha == "2":
            alvos = [r for r in resultados if r['riscos'] != "NENHUM"]
            if input(f"Confirmar exclusão de {len(alvos)} arquivos sensíveis? (S/N): ").upper() == 'S':
                s, e = actions_manager.delete_files(alvos)
                print(f"\n[FIM] Removidos: {s} | Erros: {e}")

        elif escolha == "3":
            if input(f"PERIGO: Confirmar exclusão de TODOS os {len(resultados)} itens? (S/N): ").upper() == 'S':
                s, e = actions_manager.delete_files(resultados)
                print(f"\n[FIM] Limpeza completa realizada. Removidos: {s}")

    except KeyboardInterrupt:
        print("\n\n[!] Operação cancelada pelo usuário.")
    except Exception as e:
        print(f"\n[ERRO CRÍTICO] {e}")

if __name__ == "__main__":
    main()