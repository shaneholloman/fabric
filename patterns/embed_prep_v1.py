"""
Directory Structure Markdown Generator

This script generates a comprehensive markdown document from a directory structure.
It creates a table of contents, a file tree, and code blocks for each file,
while respecting .gitignore rules and excluding archive files.

Version: 1.0.0
Date: 2024-08-20
Author: Shane Holloman

Usage:
    python directory_markdown_generator.py <path_to_directory>

Requirements:
    - pathspec

Note: This script requires Python 3.6+ for f-strings and type hinting.
"""

import os
import sys
from typing import Dict, List, Tuple
import pathspec

# Dictionary mapping file extensions to markdown code fence languages
CODE_FENCE_MAP: Dict[str, str] = {
    ".md": "markdown",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".j2": "jinja2",
    ".ini": "ini",
    ".ps1": "powershell",
    ".sh": "bash",
    ".py": "python",
    ".json": "json",
    ".js": "javascript",
    ".ts": "typescript",
    ".rb": "ruby",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "cplusplus",
    ".cs": "csharp",
    ".php": "php",
    ".go": "go",
    ".pl": "perl",
    ".lua": "lua",
    ".groovy": "groovy",
    ".conf": "ini",
    ".cfg": "ini",
    ".tf": "hcl",
    ".bat": "bat",
    "": "txt",  # Default fallback
}


def determine_code_fence(extension: str) -> str:
    """
    Determine the appropriate code fence language based on the file extension.

    Args:
        extension (str): The file extension (including the dot).

    Returns:
        str: The corresponding markdown code fence language.
    """
    return CODE_FENCE_MAP.get(extension.lower(), "txt")


def load_gitignore_specs(base_path: str) -> pathspec.PathSpec:
    """
    Load .gitignore specifications from the given base path.

    Args:
        base_path (str): The base path where the .gitignore file is located.

    Returns:
        pathspec.PathSpec: The compiled .gitignore specifications.
    """
    gitignore_path = os.path.join(base_path, ".gitignore")
    if os.path.isfile(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as file:
            return pathspec.PathSpec.from_lines("gitwildmatch", file)
    return pathspec.PathSpec.from_lines("gitwildmatch", [])


def generate_markdown_document(
    directory_path: str, gitignore_spec: pathspec.PathSpec
) -> str:
    """
    Generate a markdown document from the directory structure.

    This function traverses the directory structure, respecting .gitignore rules
    and excluding archive files. It creates a markdown document with:
    - A table of contents
    - A file tree representation
    - Code blocks for each file's content

    Args:
        directory_path (str): The path to the directory to document.
        gitignore_spec (pathspec.PathSpec): The .gitignore specifications to apply.

    Returns:
        str: The generated markdown document content.
    """
    md_content = f"# {os.path.basename(directory_path)}\n\n"
    md_content += "## Table of Contents\n\n"

    file_paths: List[str] = []
    file_tree_structure: Dict = {}
    archive_extensions = {".zip", ".tar", ".gz", ".rar", ".7z"}

    for root, dirs, files in os.walk(directory_path):
        dirs[:] = [
            d for d in dirs if not gitignore_spec.match_file(os.path.join(root, d))
        ]
        for filename in files:
            _, ext = os.path.splitext(filename)
            if ext.lower() in archive_extensions:
                continue
            file_path = os.path.join(root, filename)
            if not gitignore_spec.match_file(file_path):
                rel_path = os.path.relpath(file_path, start=directory_path)
                file_paths.append(rel_path)

                # Build file tree structure
                current_level = file_tree_structure
                for part in rel_path.split(os.sep):
                    current_level = current_level.setdefault(part, {})

    def generate_toc_and_tree(
        dir_structure: Dict, path: str = "", level: int = 0
    ) -> Tuple[str, str]:
        """
        Generate table of contents and file tree sections recursively.

        Args:
            dir_structure (Dict): The current directory structure.
            path (str): The current path in the structure.
            level (int): The current indentation level.

        Returns:
            Tuple[str, str]: The generated table of contents and file tree sections.
        """
        toc_section = ""
        tree_section = ""
        for name, val in sorted(dir_structure.items()):
            if isinstance(val, dict):
                toc_section += f"{'  ' * level}- **{name}/**\n"
                tree_section += f"{'    ' * level}{name}/\n"
                subdir_toc, subdir_tree = generate_toc_and_tree(
                    val, os.path.join(path, name), level + 1
                )
                toc_section += subdir_toc
                tree_section += subdir_tree
            else:
                toc_section += f"{'  ' * level}- [{name}]({os.path.join(path, name)})\n"
                tree_section += f"{'    ' * level}{name}\n"
        return toc_section, tree_section

    toc, file_tree = generate_toc_and_tree(file_tree_structure)
    md_content += toc
    md_content += "\n## File Tree\n\n```\n"
    md_content += file_tree
    md_content += "```\n"

    # Generate code blocks for each file
    for path in file_paths:
        md_content += f"\n### `{path}`\n\n"
        _, ext = os.path.splitext(path)
        code_fence_lang = determine_code_fence(ext)
        fence = "````" if ext == ".md" else "```"
        md_content += f"{fence}{code_fence_lang}\n"
        with open(os.path.join(directory_path, path), "r", encoding="utf-8") as file:
            md_content += file.read().rstrip() + "\n"
        md_content += f"{fence}\n"

    return md_content


def main():
    """
    Main function to orchestrate the markdown document generation process.
    """
    if len(sys.argv) != 2:
        print("Usage: python directory_markdown_generator.py <path_to_directory>")
        sys.exit(1)

    directory_path = sys.argv[1]
    if not os.path.isdir(directory_path):
        print(f"Error: '{directory_path}' is not a directory. Please check the path.")
        sys.exit(1)

    gitignore_spec = load_gitignore_specs(directory_path)
    markdown_content = generate_markdown_document(directory_path, gitignore_spec)

    markdown_filename = f"{os.path.basename(directory_path)}_structure.md"
    with open(markdown_filename, "w", encoding="utf-8") as md_file:
        md_file.write(markdown_content)

    print(f"Markdown file '{markdown_filename}' has been created.")


if __name__ == "__main__":
    main()
