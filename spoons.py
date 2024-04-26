from fastapi import HTTPException, status
from pydantic import BaseModel, EmailStr
from typing import List, Dict
from queue import Queue
import secrets
from datetime import datetime, timedelta
from fastapi_restful.tasks import repeat_every

from schemas.user_schema import UserIn
from schemas.company_schema import CompanyIn
from db import user_db, company_db
from schemas.otp_schema import UserOtpEntry, CompanyOtpEntry, QueueSchema
from schemas.user_schema import UserLogin
from schemas.company_schema import CompanyLogin
from services import auth_service

user_otp_data: Dict[str, UserOtpEntry] = {}
company_otp_data: Dict[str, CompanyOtpEntry] = {}
otp_queue: Queue[QueueSchema] = Queue()


def user_in_otp_queue(email: EmailStr):
    email_exists = any(entry.client.email == email for entry in user_otp_data.values())
    if email_exists:
        raise HTTPException(status_code=429, detail="Too many requests. Please wait before requesting another OTP.")


def company_in_otp_queue(email: EmailStr):
    email_exists = any(entry.client.email == email for entry in company_otp_data.values())
    if email_exists:
        raise HTTPException(status_code=429, detail="Too many requests. Please wait before requesting another OTP.")


def generate_register_otp(user: UserIn | CompanyIn) -> Dict:
    # Generate a 6-digit code
    otp = str(secrets.randbelow(10 ** 6))
    # Generate a hex key
    hex_key = secrets.token_hex(2).upper()  # 1 bytes = 2 hex characters

    if isinstance(user, UserIn):
        my_dict = user_otp_data
        otp_entry_class = UserOtpEntry
    else:
        my_dict = company_otp_data
        otp_entry_class = CompanyOtpEntry

    while hex_key in my_dict:
        hex_key = secrets.token_hex(2).upper()

    while len(otp) < 6:
        otp = str(secrets.randbelow(10 ** 6))

    otp_entry = otp_entry_class(otp=otp, hex_key=hex_key, client=user)

    if isinstance(user, UserIn):
        user_otp_data[hex_key] = otp_entry
        input_type = 'user'
    else:
        company_otp_data[hex_key] = otp_entry
        input_type = 'company'
    queue_item = QueueSchema(hex_key=hex_key, input_time=datetime.now(), type=input_type)
    otp_queue.put(queue_item)

    return {"code": otp, "hex_key": hex_key}


def confirm_user_otp_register(otp: str, hex_key: str):
    match = user_otp_data[hex_key]
    if not match:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OTP with given key was not found."
        )
    if match.otp == otp:
        added_user = user_db.add_user(match.client)
        del user_otp_data[hex_key]
        print(added_user)
        token = auth_service.user_login(user=UserLogin(email=match.client.email, password=match.client.password))
        print(token)
        added_user.update(token)
        return added_user
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP does not match. Access denied."
        )


def confirm_company_otp_register(otp: str, hex_key: str):
    match = company_otp_data[hex_key]
    if not match:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OTP with given key was not found."
        )
    if match.otp == otp:
        added_user = company_db.add_company(match.client)
        del company_otp_data[hex_key]
        token = auth_service.company_login(
            company=CompanyLogin(email=match.client.email, password=match.client.password))
        added_user.update(token)
        return added_user
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP does not match. Access denied."
        )


@repeat_every(seconds=1, wait_first=True)
async def remove_expired_otp():
    duration = timedelta(minutes=3)
    time = datetime.now()

    while not otp_queue.empty() and (time - otp_queue.queue[0].input_time) >= duration:
        queue_item = otp_queue.get()
        print(f"Processing queue item: {queue_item.hex_key}")

        if queue_item.type == 'user':
            user_otp_data.pop(queue_item.hex_key, None)
        elif queue_item.type == 'company':
            company_otp_data.pop(queue_item.hex_key, None)

        print(f"User data: {user_otp_data}")
        print(f"Company data: {company_otp_data}")
