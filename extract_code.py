#!/usr/bin/env python3
import re
import os
import sys
from pathlib import Path
from typing import Optional, Tuple, List


class CodeExtractor:
    def __init__(self, input_file: str):
        self.input_file = input_file
        self.content = self.read_file()
        self.extracted_files = []

    def read_file(self) -> str:
        """Lê o conteúdo do arquivo de entrada"""
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            print(f"Erro: Arquivo '{self.input_file}' não encontrado")
            sys.exit(1)
        except Exception as e:
            print(f"Erro ao ler arquivo: {e}")
            sys.exit(1)

    def extract_code_blocks(self) -> List[Tuple[str, str, str, int]]:
        """
        Extrai blocos de código do conteúdo.
        Retorna lista de (linguagem, caminho, código, linha_inicio)
        """
        blocks = []

        # Padrão para encontrar blocos de código
        # Grupos: (1) linguagem, (2) conteúdo do bloco
        pattern = r'```(\w+)\s*\n(.*?)\n```'

        # Encontra todas as posições dos blocos
        matches = list(re.finditer(pattern, self.content, re.DOTALL | re.MULTILINE))

        for match in matches:
            language = match.group(1).lower()
            block_content = match.group(2)

            # Encontra a linha onde começa o bloco
            line_start = self.content[:match.start()].count('\n') + 1

            # Extrai o caminho da primeira linha (se existir)
            path = self.extract_path_from_first_line(block_content, language)

            blocks.append((language, path, block_content, line_start))

        return blocks

    def extract_path_from_first_line(self, content: str, language: str) -> Optional[str]:
        """
        Extrai o caminho do arquivo da primeira linha do bloco de código.
        Retorna None se não encontrar um caminho válido.
        """
        lines = content.strip().split('\n')
        if not lines:
            return None

        first_line = lines[0].strip()

        # Padrões para diferentes linguagens
        patterns = {
            'rust': r'^//\s+(.+\.rs)$',
            'python': r'^#\s+(.+\.py)$',
            'yaml': r'^#\s+(.+\.ya?ml)$',
        }

        if language in patterns:
            match = re.match(patterns[language], first_line)
            if match:
                return match.group(1)

        return None

    def should_include_path_line(self, content: str, language: str, has_path: bool) -> str:
        """
        Decide se deve incluir a linha do caminho no arquivo de saída.
        Remove a linha do caminho se ele foi extraído para uso no diretório.
        """
        lines = content.split('\n')

        # Se não tem caminho ou é um exemplo, mantém a primeira linha
        if not has_path:
            return content

        # Remove a primeira linha (caminho) se ela for um comentário de caminho
        if language == 'rust' and lines[0].startswith('// ') and '.rs' in lines[0]:
            return '\n'.join(lines[1:])
        elif language == 'python' and lines[0].startswith('# ') and '.py' in lines[0]:
            return '\n'.join(lines[1:])
        elif language == 'yaml' and lines[0].startswith('# ') and ('.yaml' in lines[0] or '.yml' in lines[0]):
            return '\n'.join(lines[1:])

        return content

    def save_code_block(self, language: str, path: Optional[str],
                        content: str, block_num: int) -> str:
        """
        Salva o bloco de código em um arquivo.
        Retorna o caminho do arquivo salvo.
        """
        # Define a extensão baseada na linguagem
        extensions = {
            'rust': '.rs',
            'python': '.py',
            'yaml': '.yaml',
        }

        ext = extensions.get(language, '.txt')

        # Se tem caminho específico, usa ele
        if path:
            file_path = Path(path)
            # Cria diretórios se não existirem
            file_path.parent.mkdir(parents=True, exist_ok=True)
            output_path = str(file_path)
        else:
            # Salva em diretório genérico para exemplos
            generic_dir = Path("extracted_examples")
            generic_dir.mkdir(exist_ok=True)

            # Subdiretório por linguagem
            lang_dir = generic_dir / language
            lang_dir.mkdir(exist_ok=True)

            output_path = str(lang_dir / f"example_{block_num:03d}{ext}")

        # Prepara o conteúdo para salvar
        content_to_save = self.should_include_path_line(content, language, path is not None)

        # Salva o arquivo
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content_to_save)

        return output_path

    def extract_and_save(self):
        """Processa o arquivo e extrai todos os blocos de código"""
        print(f"Processando arquivo: {self.input_file}")
        print("-" * 50)

        blocks = self.extract_code_blocks()

        if not blocks:
            print("Nenhum bloco de código encontrado.")
            return

        print(f"Encontrados {len(blocks)} blocos de código:")
        print("-" * 50)

        for i, (language, path, content, line_start) in enumerate(blocks, 1):
            # Conta linhas no bloco
            lines = content.count('\n') + 1

            print(f"\nBloco {i}:")
            print(f"  Linha inicial: {line_start}")
            print(f"  Linguagem: {language}")
            print(f"  Linhas de código: {lines}")

            if path:
                print(f"  Caminho destino: {path}")
                output_path = self.save_code_block(language, path, content, i)
            else:
                print(f"  Caminho destino: [exemplo genérico]")
                output_path = self.save_code_block(language, None, content, i)

            self.extracted_files.append(output_path)
            print(f"  Salvo em: {output_path}")

        print("\n" + "=" * 50)
        print(f"Extração concluída!")
        print(f"Total de arquivos salvos: {len(self.extracted_files)}")

        # Cria um relatório de extração
        self.create_extraction_report()

    def create_extraction_report(self):
        """Cria um arquivo de relatório com os arquivos extraídos"""
        report_path = "extraction_report.txt"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"Relatório de Extração - {self.input_file}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Arquivos extraídos: {len(self.extracted_files)}\n\n")

            for i, file_path in enumerate(self.extracted_files, 1):
                f.write(f"{i:3d}. {file_path}\n")

        print(f"Relatório gerado em: {report_path}")


def main():
    """Função principal"""
    if len(sys.argv) != 2:
        print("Uso: python extract_code.py <arquivo_markdown_ou_txt>")
        print("Exemplo: python extract_code.py documentacao.md")
        sys.exit(1)

    input_file = sys.argv[1]

    # Verifica se o arquivo existe
    if not os.path.exists(input_file):
        print(f"Erro: Arquivo '{input_file}' não encontrado")
        sys.exit(1)

    # Processa o arquivo
    extractor = CodeExtractor(input_file)
    extractor.extract_and_save()


if __name__ == "__main__":
    main()