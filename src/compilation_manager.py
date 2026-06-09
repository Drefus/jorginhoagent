"""Compilation Manager — compila código Java/C# via Docker quando necessário."""

import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple


class CompilationResult:
    """Resultado de uma compilação."""

    def __init__(self, success: bool, output_path: Optional[str] = None, error: str = ""):
        self.success = success
        self.output_path = output_path  # Diretório com artefatos compilados
        self.error = error


class CompilationManager:
    """Gerencia compilação de código para linguagens que necessitam."""

    def __init__(self):
        self._docker_available: Optional[bool] = None

    def needs_compilation(self, language: str) -> bool:
        """Verifica se a linguagem precisa de compilação."""
        return language in ("java", "csharp")

    def compile(self, code: str, language: str, file_path: str = "code") -> CompilationResult:
        """Compila o código se necessário.

        Args:
            code: Código-fonte.
            language: Linguagem detectada.
            file_path: Caminho original do arquivo.

        Returns:
            CompilationResult com status e caminho dos artefatos.
        """
        if not self.needs_compilation(language):
            return CompilationResult(success=True)

        if not self._check_docker():
            return CompilationResult(
                success=False,
                error="Docker não disponível. Compilação requer Docker."
            )

        if language == "java":
            return self._compile_java(code, file_path)
        elif language == "csharp":
            return self._compile_csharp(code, file_path)

        return CompilationResult(success=True)

    def _compile_java(self, code: str, file_path: str) -> CompilationResult:
        """Compila código Java usando Docker com JDK."""
        try:
            # Cria diretório temporário com o arquivo
            tmp_dir = tempfile.mkdtemp(prefix="jorginho_java_")
            # Extrai nome da classe do arquivo
            filename = Path(file_path).stem + ".java"
            src_file = Path(tmp_dir) / filename
            src_file.write_text(code, encoding="utf-8")

            tmp_dir_docker = str(tmp_dir).replace("\\", "/")
            cmd = [
                "docker", "run", "--rm",
                "--memory=512m",
                "-v", f"{tmp_dir_docker}:/src",
                "-w", "/src",
                "eclipse-temurin:17-jdk",
                "javac", f"/src/{filename}",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                error_msg = result.stderr[:5000] if result.stderr else "Compilação falhou sem mensagem"
                print(f"  [Compilation] Java falhou: {error_msg[:200]}")
                return CompilationResult(success=False, error=error_msg)

            print(f"  [Compilation] Java compilado com sucesso")
            return CompilationResult(success=True, output_path=tmp_dir)

        except subprocess.TimeoutExpired:
            return CompilationResult(success=False, error="Compilação Java excedeu timeout de 120s")
        except (FileNotFoundError, OSError) as e:
            return CompilationResult(success=False, error=f"Erro ao compilar Java: {e}")

    def _compile_csharp(self, code: str, file_path: str) -> CompilationResult:
        """Compila código C# usando Docker com .NET SDK."""
        try:
            tmp_dir = tempfile.mkdtemp(prefix="jorginho_csharp_")
            filename = Path(file_path).stem + ".cs"
            src_file = Path(tmp_dir) / filename
            src_file.write_text(code, encoding="utf-8")

            # Cria um .csproj mínimo
            csproj = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Library</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>"""
            (Path(tmp_dir) / "project.csproj").write_text(csproj, encoding="utf-8")

            tmp_dir_docker = str(tmp_dir).replace("\\", "/")
            cmd = [
                "docker", "run", "--rm",
                "--memory=512m",
                "-v", f"{tmp_dir_docker}:/src",
                "-w", "/src",
                "mcr.microsoft.com/dotnet/sdk:8.0",
                "dotnet", "build", "--nologo", "-q",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                error_msg = result.stderr[:5000] if result.stderr else result.stdout[:5000]
                print(f"  [Compilation] C# falhou: {error_msg[:200]}")
                return CompilationResult(success=False, error=error_msg)

            print(f"  [Compilation] C# compilado com sucesso")
            return CompilationResult(success=True, output_path=tmp_dir)

        except subprocess.TimeoutExpired:
            return CompilationResult(success=False, error="Compilação C# excedeu timeout de 120s")
        except (FileNotFoundError, OSError) as e:
            return CompilationResult(success=False, error=f"Erro ao compilar C#: {e}")

    def _check_docker(self) -> bool:
        """Verifica se Docker está disponível."""
        if self._docker_available is not None:
            return self._docker_available
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._docker_available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._docker_available = False
        return self._docker_available
