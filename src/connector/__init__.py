from typing import Dict

from .baseConnector import Connector
from .chatGPT import ChatGPT
from .gemini import Gemini

connector_registry: Dict[str, Connector] = {}


def register_connector(name: str, connector: Connector) -> None:
    if not isinstance(connector, Connector):
        raise ValueError(f"{connector} is not a subclass of Connector")
    connector_registry[name.lower()] = connector


def get_connector(model_name: str) -> Connector:
    connector = connector_registry.get(model_name.lower())

    if connector is None:
        try:
            key = model_name.lower()
            if key in {"gpt-3.5-turbo", "gpt-3.5-turbo-16k", "gpt-4", "gpt-4.1-mini"}:
                try:
                    connector = ChatGPT(key)
                except Exception as e:
                    raise ValueError(f"Failed to initialize ChatGPT connector {model_name}: {type(e).__name__}: {str(e)}")
                register_connector(key, connector)
            elif key in {"gemini-1.5-flash-latest", "gemini-2.5-flash-lite", "gemini-2.0-flash-lite-001"}:
                try:
                    connector = Gemini(key)
                except Exception as e:
                    raise ValueError(f"Failed to initialize Gemini connector {model_name}: {type(e).__name__}: {str(e)}")
                register_connector(key, connector)
            else:
                raise ValueError(f"Unknown connector: {model_name}")
        except Exception as e:
            raise ValueError(f"Failed to initialize connector {model_name}: {e}")

    return connector
