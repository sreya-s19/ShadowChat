import bleach
from flask import request, current_app
from flask_login import current_user
from flask_socketio import emit, join_room, leave_room
from sqlalchemy import or_

from .extensions import db, socketio
from .models import User, Message

user_sid_map = {}

@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        user_id = current_user.id
        user_sid_map[user_id] = request.sid
        join_room(user_id)
        print(f"Client connected: {current_user.username}, SID: {request.sid}")
        emit('update_user_list', list(user_sid_map.keys()), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        user_id = current_user.id
        if user_id in user_sid_map:
            del user_sid_map[user_id]
            leave_room(user_id)
            print(f"Client disconnected: {current_user.username}")
            emit('update_user_list', list(user_sid_map.keys()), broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    """
    Handles receiving a message, checks for keywords, saves it to the
    database, and then emits it to the recipient.
    """
    if not current_user.is_authenticated:
        return

    recipient_id = int(data['recipient_id'])
    body_raw = data['body']
    is_encrypted = data.get('is_encrypted', False)
    
    # Sanitize input to prevent XSS
    sanitized_body = bleach.clean(body_raw)

    # --- KEYWORD ALERT LOGIC ---
    has_alert = False
    # Check for keywords in the plaintext message
    message_lower = sanitized_body.lower()
    for keyword in current_app.config['CYBERCRIME_KEYWORDS']:
        if keyword in message_lower:
            has_alert = True
            break # Found a keyword, no need to check further

    # Create and save the message
    message = Message(sender_id=current_user.id, recipient_id=recipient_id)
    if is_encrypted:
        message.encrypt_body(sanitized_body)
    else:
        message.body = sanitized_body
    
    db.session.add(message)
    db.session.commit()

    # Prepare message data to send back to clients
    message_data = {
        'message_id': message.id,
        'sender_id': current_user.id,
        'sender_username': current_user.username,
        'recipient_id': recipient_id, # Added recipient_id for frontend logic
        'body': message.body,
        'is_encrypted': message.is_encrypted,
        'timestamp': message.timestamp.isoformat(),
        'alert': has_alert # <-- ADD THE ALERT FLAG
    }
    
    # Send to recipient if they are online
    if recipient_id in user_sid_map:
        emit('receive_message', message_data, room=user_sid_map[recipient_id])

    # Also send to the sender's own client
    emit('receive_message', message_data, room=request.sid)

@socketio.on('get_history')
def handle_get_history(data):
    if not current_user.is_authenticated:
        return
        
    other_user_id = int(data['recipient_id'])
    
    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.recipient_id == other_user_id),
            (Message.sender_id == other_user_id) & (Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp.asc()).all()

    history = [
        {
            'message_id': msg.id, # <-- ADD THIS
            'sender_id': msg.sender_id,
            'sender_username': msg.sender.username,
            'body': msg.body, # <-- CHANGED: Send raw body
            'is_encrypted': msg.is_encrypted,
            'timestamp': msg.timestamp.isoformat()
        } for msg in messages
    ]
    emit('chat_history', history)

@socketio.on('typing')
def handle_typing(data):
    if not current_user.is_authenticated:
        return
        
    recipient_id = int(data['recipient_id'])
    if recipient_id in user_sid_map:
        emit('typing_status', {
            'sender_id': current_user.id,
            'is_typing': data['is_typing']
        }, room=user_sid_map[recipient_id])

# --- NEW EVENT HANDLER ---
@socketio.on('decrypt_message')
def handle_decrypt_message(data):
    """Handles a client's request to decrypt a specific message."""
    if not current_user.is_authenticated:
        return

    message_id = data.get('message_id')
    message = Message.query.get(message_id)

    # Security check: Ensure the user is part of the conversation
    if message and (message.sender_id == current_user.id or message.recipient_id == current_user.id):
        plaintext = message.decrypt_body()
        emit('decryption_result', {'message_id': message_id, 'plaintext': plaintext})