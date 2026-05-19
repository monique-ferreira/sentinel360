"""
main.py — CLI do Sentinel360

Interface de linha de comando para executar varredura, gerar relatório
e tomar ações de remediação sem precisar do servidor web.
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv()

import scanner_engine
import actions_manager


def main():
    print("=" * 60)
    print("        SENTINEL 360 — CYBER DEFENSE PLATFORM")
    print("=" * 60)

    try:
        dias_input = input("\nDias para considerar inatividade [padrão: 180]: ").strip()
        dias = int(dias_input) if dias_input else 180
        if dias < 1 or dias > 3650:
            print("[!] Valor inválido. Usando 180 dias.")
            dias = 180

        print(f"\n[1/3] Iniciando varredura (limiar: {dias} dias)...")

        class FakeState:
            is_scanning    = True
            progress       = 0.0
            total_files    = 0
            processed_files = 0
            eta_seconds    = 0
            start_time     = 0.0

        state = FakeState()
        resultados = scanner_engine.run_full_scan(dias, state)

        if not resultados:
            print("\n[✓] Nenhum arquivo de risco ou inativo encontrado.")
            return

        print(f"[2/3] Varredura concluída. {len(resultados)} itens encontrados.")

        # Resumo
        resumo = actions_manager.summarize(resultados)
        print(f"\n  Inativos:    {resumo['inativos']}")
        print(f"  Com riscos:  {resumo['com_risco']}")
        print(f"  Storage:     {resumo['total_mb']} MB")
        if resumo["risk_types"]:
            print("  Tipos de risco:")
            for tipo, qtd in sorted(resumo["risk_types"].items(), key=lambda x: -x[1]):
                print(f"    · {tipo}: {qtd}")

        # Exportar CSV automaticamente
        actions_manager.export_to_csv(resultados)

        # Menu de remediação
        print("\n" + "-" * 40)
        print("MENU DE REMEDIAÇÃO:")
        print("  1. Listar todos os arquivos encontrados")
        print("  2. Remover APENAS arquivos com riscos/credenciais")
        print("  3. Remover TUDO (inativos + com risco)")
        print("  4. Sair sem alterar nada")
        print("-" * 40)

        escolha = input("Opção: ").strip()

        if escolha == "1":
            print()
            for i, r in enumerate(resultados):
                flag = "[!]" if r["riscos"] != "NENHUM" else "[ ]"
                print(f"  {flag} [{i+1:04d}] {r['riscos']:<20} {r['caminho']}")

        elif escolha == "2":
            alvos = [r for r in resultados if r["riscos"] not in ("NENHUM", "")]
            if not alvos:
                print("[OK] Nenhum arquivo com risco para remover.")
                return
            confirm = input(
                f"\n[AVISO] Confirmar exclusão de {len(alvos)} arquivo(s) sensível(is)? (S/N): "
            ).strip().upper()
            if confirm == "S":
                s, e = actions_manager.delete_files(alvos)
                print(f"\n[FIM] Removidos: {s} | Erros: {e}")
            else:
                print("[!] Operação cancelada.")

        elif escolha == "3":
            confirm = input(
                f"\n[PERIGO] Confirmar exclusão de TODOS os {len(resultados)} item(ns)? (S/N): "
            ).strip().upper()
            if confirm == "S":
                s, e = actions_manager.delete_files(resultados)
                print(f"\n[FIM] Limpeza concluída. Removidos: {s} | Erros: {e}")
            else:
                print("[!] Operação cancelada.")

        else:
            print("\n[OK] Saindo sem alterações. Relatório CSV salvo.")

    except KeyboardInterrupt:
        print("\n\n[!] Operação cancelada pelo usuário.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERRO CRÍTICO] {e}")
        raise


if __name__ == "__main__":
    main()
