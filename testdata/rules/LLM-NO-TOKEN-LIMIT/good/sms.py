from twilio.rest import Client

client = Client(sid, tok)
client.messages.create(to="+15550001111", body="hi")
