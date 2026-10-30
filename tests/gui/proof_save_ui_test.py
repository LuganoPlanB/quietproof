"""Native Save As flow with a freshly generated proof, real verification and CLI interoperability."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import itertools,json,os
from pathlib import Path
import re,struct,subprocess,sys,tempfile,threading
sys.dont_write_bytecode=True
from wallet_session_fixture import Server


class ChainHandler(BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_POST(self):
        server=self.server
        with server.condition: server.active+=1
        try:
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            method=body['method']; server.calls.append(method)
            assert method in ('getblockchaininfo','gettxout'), 'unexpected verification RPC'
            result={'chain':'regtest','blocks':100,'bestblockhash':'ab'*32}
            if method=='gettxout':
                result={'bestblock':'ab'*32,'confirmations':10,'value':0.00000001,
                        'scriptPubKey':{'hex':'0014751e76e8199196d454941c45d1b3a323f1433bd6'}}
            data=json.dumps({'jsonrpc':'2.0','id':body['id'],'result':result}).replace('"value": 1e-08','"value": 0.00000001').encode()
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError): pass
        except Exception: server.violation='chain fixture assertion failed'
        finally:
            with server.condition: server.active-=1;server.condition.notify_all()


def main():
    gui,driver,cli,proof,artifacts=map(lambda p:Path(p).resolve(),sys.argv[1:6])
    artifacts.mkdir(parents=True,exist_ok=True); records=[]
    with tempfile.TemporaryDirectory(prefix='quietproof-save-ui-') as directory:
        root=Path(directory); request=root/'reviewed.qpr'
        subprocess.run([str(driver),str(proof),str(request),'--prepare-request'],check=True,capture_output=True,timeout=5)
        env=dict(os.environ,SDL_VIDEODRIVER='dummy',SDL_RENDER_DRIVER='software',XDG_DATA_HOME=directory,HOME=directory)
        wallet=Server();wallet.scenario='unlocked'
        wallet_thread=threading.Thread(target=wallet.serve_forever);wallet_thread.start()
        cookie=root/'.cookie';cookie.write_text('__cookie__:'+''.join(chr(97+i) for i in range(12)));cookie.chmod(0o600)
        preferences=root/'Plan-B/quietproof';preferences.mkdir(parents=True)
        fields=['127.0.0.1',str(wallet.server_port),'',str(cookie),'','3000','3000']
        configuration='quietproof-node=1\n'+''.join(f'{i} {json.dumps(v)}\n' for i,v in enumerate(fields))
        (preferences/'node.conf').write_text(configuration);(preferences/'node.conf').chmod(0o600)
        # Exercise the normal approval/RPC/prover/result journey once. The
        # preexisting unlocked synthetic wallet needs no password or relock.
        events=['control 3','control 11']+['wait']*12+['control 2','control 304','await-proof']
        def capture(name,theme='light',size=(480,720),scale='1',matrix=False):
            events.append('capture '+str(artifacts/(name+'.bmp')))
            records.append({'name':name,'theme':theme,'width':size[0],'height':size[1],'font_scale':scale,'matrix':matrix})
        expected=[]; first_saved=None
        for error,theme,size,scale in itertools.product((False,True),('light','dark'),((400,640),(480,720)),('1','1.5')):
            name=f"{'save-error' if error else 'success'}-{theme}-{size[0]}x{size[1]}-{scale}"
            destination=root/('absent/fail.qpf' if error else name+'.qpf')
            # Use actual Display controls; resizing is a bounded rendering event.
            events+=['resize '+str(size[0])+' '+str(size[1]),'control 1','control '+('5' if theme=='light' else '6'),
                     'control '+('7' if scale=='1' else '9'),'control 11','control 4','control 11',
                     'destination '+str(destination),'control 307','await-save']
            capture(name,theme,size,scale,True)
            if error: events+=['control 308']
            else: first_saved=destination
            expected.append((destination,error))
        # All following cases share the same verified public bytes. No new key,
        # fixture validation or unlock is needed to recover from output failures.
        events+=['resize 480 720','control 1','control 5','control 7','control 11','control 4']
        old=b'previous public output'
        refused=root/'refused.qpf'; refused.write_bytes(old)
        events+=['control 11','destination '+str(refused),'control 307','await-save']
        capture('overwrite-refused'); events+=['control 308']
        replaced=root/'confirmed.qpf'; replaced.write_bytes(old)
        events+=['control 11','destination '+str(replaced),'control 307','await-save','control 307','await-save']
        capture('overwrite-confirmed')
        previous=root/'previous.qpf'; previous.write_bytes(old)
        other=root/'other.qpf'; other.write_bytes(b'different public output')
        events+=['control 11','destination '+str(previous),'control 307','await-save','destination '+str(other),'control 307','await-save']
        capture('destination-changed'); events+=['control 308']
        retried=root/'retried.qpf'
        events+=['control 11','destination '+str(root/'absent/fail.qpf'),'control 307','await-save',
                 'destination '+str(retried),'control 307','await-save']
        capture('save-retry')
        canceled=root/'canceled.qpf'
        events+=['control 11','destination '+str(canceled),'control 308']
        capture('dialog-cancel')
        script=artifacts/'matrix.events'; script.write_text('\n'.join(events)+'\n')
        command=[str(gui),'--smoke-test','--request',str(request),'--test-events',str(script),'--width','480','--height','720']
        try: value=subprocess.run(command,env=env,capture_output=True,text=True,timeout=240)
        finally:
            wallet.release.set();wallet.idle();wallet.shutdown();wallet.server_close();wallet_thread.join(timeout=4)
            assert not wallet_thread.is_alive() and wallet.active==0, 'wallet fixture cleanup incomplete'
        (artifacts/'matrix.log').write_text(value.stdout+value.stderr)
        assert value.returncode==0, 'native Save As matrix failed'
        assert value.stdout.count('GUI proof stage: 5')==1, 'matrix must share one native verification'
        assert 'GUI proof stage: 3' in value.stdout, 'normal GUI native proving was not observed'
        assert not wallet.violation and (preferences/'node.conf').read_text()==configuration
        wallet_methods=[v['method'] for v in wallet.calls]
        assert wallet_methods.count('exportaddresskey')==1 and not set(wallet_methods)&{'walletpassphrase','walletlock'}, 'GUI proof repeated key access or changed preexisting lock state'
        rows=re.findall(r'^GUI capture: (\d+) retained=(\d) confirm=(\d) dialog=(\d) busy=(\d) status=(\d)$',value.stdout,re.M)
        assert len(rows)==len(records), 'capture selection mismatch'
        controls={}
        for r in re.findall(r'^GUI capture control: (\d+) (\d+) ([\d.-]+) ([\d.-]+) ([\d.-]+) ([\d.-]+)$',value.stdout,re.M):
            controls.setdefault(int(r[0]),{})[int(r[1])]=tuple(map(float,r[2:]))
        for row,record in zip(rows,records):
            index,retained,confirm,dialog,busy,status=map(int,row)
            assert retained==1 and busy==0, 'verified proof lost or operation did not settle'
            record.update(index=index,exit=value.returncode,retained=retained,confirm=confirm,dialog=dialog,status=status,remaining_operations=0)
            size=(record['width'],record['height'])
            assert struct.unpack_from('<ii',(artifacts/(record['name']+'.bmp')).read_bytes(),18)==size
            for control in ((307,308) if dialog else (11,)):
                x,y,w,h=controls[index][control]
                assert 0<=x<x+w<=size[0] and size[1]-100<y<y+h<=size[1], 'fixed save action clipped'
        wire=first_saved.read_bytes()
        saved_request=root/'saved-request.qpr'
        subprocess.run([str(driver),str(first_saved),str(saved_request),'--prepare-request'],check=True,capture_output=True,timeout=5)
        assert saved_request.read_bytes()==request.read_bytes(), 'saved GUI proof changed the exact reviewed statement'
        for destination,error in expected:
            assert (not destination.exists()) if error else destination.read_bytes()==wire
        by_name={v['name']:v for v in records}
        assert refused.read_bytes()==old and by_name['overwrite-refused']['confirm']==1
        assert replaced.read_bytes()==wire and by_name['overwrite-confirmed']['confirm']==0
        assert previous.read_bytes()==old and other.read_bytes()==b'different public output' and by_name['destination-changed']['confirm']==1
        assert retried.read_bytes()==wire and not canceled.exists()
        assert not list(root.rglob('.quietproof-*')), 'temporary output survived GUI cases'
        # Current CLI uses controlled public chain evidence. This is synthetic
        # interoperability, not live Roots/current-chain qualification.
        server=ThreadingHTTPServer(('127.0.0.1',0),ChainHandler)
        server.condition=threading.Condition();server.active=0;server.calls=[];server.violation=None
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            cookie=root/'.cookie';cookie.write_text('__cookie__:'+''.join(chr(97+i) for i in range(12)));cookie.chmod(0o600)
            command=[str(cli),'verify',str(first_saved),'--verifier','proof-session.example','--purpose','proof-of-control',
                     '--nonce-store',str(root/'nonces'),'--network','regtest','--rpc-url',f'http://127.0.0.1:{server.server_port}/','--rpc-cookie',str(cookie)]
            verified=subprocess.run(command,capture_output=True,text=True,timeout=120)
            (artifacts/'cli-verify.json').write_text(verified.stdout);(artifacts/'cli-verify.stderr').write_text(verified.stderr)
            (artifacts/'chain-calls.json').write_text(json.dumps({'calls':server.calls,'violation':server.violation})+'\n')
            assert verified.returncode==0 and json.loads(verified.stdout)['result']=='valid_current', 'current CLI rejected GUI-saved native proof'
            inspected=subprocess.run([str(cli),'inspect',str(first_saved)],capture_output=True,text=True,timeout=10)
            (artifacts/'cli-inspect.json').write_text(inspected.stdout)
            assert inspected.returncode==0 and json.loads(inspected.stdout)['format']=='quietproof-proof-v2'
            assert not server.violation
            with server.condition: assert server.condition.wait_for(lambda:server.active==0,4)
            cli_record={'verify_command':command,'verify_exit':verified.returncode,'inspect_exit':inspected.returncode,
                        'calls':server.calls,'remaining_operations':server.active,'evidence':'synthetic current-chain fixture only'}
        finally:
            server.shutdown();server.server_close();thread.join(timeout=4)
            assert not thread.is_alive() and server.active==0
        (artifacts/'gui-saved.qpf').write_bytes(first_saved.read_bytes())
    (artifacts/'summary.json').write_text(json.dumps({'records':records,'captures':16,'native_generations':1,'native_verifications':1,'wallet_calls':wallet.calls,'cli':cli_record,'held_operations':0,'in_flight_operations':0},indent=2)+'\n')
    print(f'Proof Save UI: {len(records)} scenarios,16 native success/error captures; CLI verify/inspect passed; held=0 in-flight=0')


if __name__=='__main__':main()
