import gettext
import os

current_dir = os.path.dirname(os.path.realpath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, os.pardir))


def get_translation_func(lang: str):
    if not lang:
        return gettext.gettext

    try:
        return gettext.translation("messages", localedir=f"{root_dir}/gettext", languages=[lang]).gettext
    except FileNotFoundError:
        return gettext.gettext
