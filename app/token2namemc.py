import sys
from time import time
from twisted.internet import defer, reactor
from quarry.net.auth import Profile
from quarry.net.client import ClientFactory, SpawningClientProtocol
import multiprocessing

the_link = ""


class MinecraftProtocol(SpawningClientProtocol):
    gottaSendCmd = True

    def packet_system_message(self, buff):
        msg = str(buff.unpack_chat().to_string())
        buff.discard()
        if (self.gottaSendCmd):
            d = [self.buff_type.pack_string('namemc'),
                 self.buff_type.pack('QQ', int(time()*1000), 0),
                 self.buff_type.pack_byte_array(b''),
                 self.buff_type.pack('?', False),
                 self.buff_type.pack_last_seen_list([]), 
                 self.buff_type.pack('?', False)
                ]
            self.send_packet('chat_command', *d)
            self.gottaSendCmd = False

        if (msg.startswith('https')):
            global the_link
            the_link = msg
            reactor.stop()


class MinecraftFactory(ClientFactory):
    protocol = MinecraftProtocol


@defer.inlineCallbacks
def run(token, name, uuid):
    profile = yield Profile.from_token('', token, name, uuid)
    factory = MinecraftFactory(profile)
    factory.connect('blockmania.com', 25565)

def main(token, name, uuid, result_queue):
    run(token, name, uuid)
    reactor.run()
    if result_queue:
        result_queue.put(the_link)
    return the_link

def wrapper(token, name, uuid):
    result_queue = multiprocessing.Queue()
    
    p = multiprocessing.Process(target=main, args=(token, name, uuid, result_queue))
    p.start()
    p.join(5)
    if p.is_alive():
        p.terminate()
    
    return result_queue.get()
