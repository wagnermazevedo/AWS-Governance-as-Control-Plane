"""Estado do modo gravação (lib/mask.py) entre testes: cada teste começa limpo e
com uma chave fixa, sem gravar outputs/.mask-key no repositório."""

import contextlib
import sys
from unittest import mock

from lib import mask

TEST_KEY = b"chave-de-teste-do-modo-gravacao!"


def reset_mask(key=TEST_KEY):
    mask._ENABLED = True
    mask._KEEP_PREFIXES = ()
    mask._LEARNED.clear()
    mask._ALIASES.clear()
    mask._KEY = key


@contextlib.contextmanager
def isolated_streams():
    """O mask.setup troca sys.stdout/sys.stderr: devolve os originais ao sair."""
    with mock.patch.object(sys, "stdout", sys.stdout), mock.patch.object(sys, "stderr", sys.stderr):
        yield
