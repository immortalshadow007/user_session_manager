from channels.generic.websocket import AsyncWebsocketConsumer
import json

class SessionManageConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Accept the WebSocket connection
        await self.accept()
        await self.send(text_data=json.dumps({
            'message': 'WebSocket connection established!',
        }))

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        # Handle incoming messages from the WebSocket
        text_data_json = json.loads(text_data)
        message = text_data_json.get('message', '')

        # Echo the received message back to the client
        await self.send(text_data=json.dumps({
            'message': f'You sent: {message}',
        }))
