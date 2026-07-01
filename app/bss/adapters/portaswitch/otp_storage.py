import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, UTC
from typing import Any, Optional, Tuple

from bss.dbs import TiedKeyValue


class OtpStorage(ABC):

    @abstractmethod
    def store(self, otp_id: str, i_account: Any, user_id: str, bss_token: Optional[str] = None) -> None:
        pass

    @abstractmethod
    def retrieve(self, otp_id: str) -> Tuple[Any, Optional[str], Optional[str]]:
        pass

    @abstractmethod
    def delete(self, otp_id: str) -> None:
        pass


class OtpStorageInMemory(OtpStorage):

    def __init__(self):
        self._db = TiedKeyValue()
        logging.warning("OTP storage: in-process memory (not safe for multi-instance deployments)")

    def store(self, otp_id: str, i_account: Any, user_id: str, bss_token: Optional[str] = None) -> None:
        self._db[otp_id] = (i_account, user_id, bss_token)

    def retrieve(self, otp_id: str) -> Tuple[Any, Optional[str], Optional[str]]:
        return self._db.get(otp_id, (None, None, None))

    def delete(self, otp_id: str) -> None:
        self._db.pop(otp_id, None)


class OtpStorageFirestore(OtpStorage):
    """Shared across all adapter instances.

    Credentials:
        On GCP:     ADC is used automatically.
        Off GCP:    set GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

    TTL cleanup:
        Configure a Firestore TTL policy on the expires_at field of the collection
        (one-time setup in GCP Console or via Terraform).
    """

    def __init__(self, collection_name: str, ttl_minutes: int = 30):
        from bss.dbs.firestore import FirestoreKeyValue
        self._db = FirestoreKeyValue(collection_name=collection_name)
        self._ttl_minutes = ttl_minutes
        logging.info(f"OTP storage: Firestore collection '{collection_name}'")

    def store(self, otp_id: str, i_account: Any, user_id: str, bss_token: Optional[str] = None) -> None:
        self._db[otp_id] = {
            "i_account": i_account,
            "user_id": user_id,
            "bss_token": bss_token,
            "expires_at": datetime.now(UTC) + timedelta(minutes=self._ttl_minutes),
        }

    def retrieve(self, otp_id: str) -> Tuple[Any, Optional[str], Optional[str]]:
        record = self._db.get(otp_id)
        if not record:
            return None, None, None
        return record.get("i_account"), record.get("user_id"), record.get("bss_token")

    def delete(self, otp_id: str) -> None:
        self._db.pop(otp_id, None)


def configure_otp_storage(settings) -> OtpStorage:
    if settings.STORAGE_COLLECTION:
        return OtpStorageFirestore(
            collection_name=settings.STORAGE_COLLECTION,
            ttl_minutes=settings.STORAGE_TTL_MINUTES,
        )
    return OtpStorageInMemory()
