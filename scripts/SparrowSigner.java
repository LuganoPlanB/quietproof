// Adapter over the user's explicitly supplied Sparrow distribution; no crypto implementation.
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import com.google.gson.*;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.crypto.*;
import com.sparrowwallet.drongo.policy.*;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.io.Storage;

public class SparrowSigner {
    private static final Gson JSON = new Gson();

    private static String message(String path) throws Exception {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(Files.readAllBytes(Path.of(path)))).toString();
    }

    public static void main(String[] args) {
        try {
            run(args);
            System.exit(0);
        } catch(Exception error) {
            // Exceptions from wallet libraries can contain sensitive material.
            System.err.println("Sparrow adapter rejected operation (" + error.getClass().getSimpleName() + ")");
            System.exit(1);
        }
    }

    private static void run(String[] args) throws Exception {
        String action=args[0];
        Network network=switch(args[1]) {
            case "signet" -> Network.SIGNET;
            case "testnet4" -> Network.TESTNET4;
            case "regtest" -> Network.REGTEST;
            default -> throw new IllegalArgumentException("test network required");
        };
        Network.set(network);
        ScriptType type=ScriptType.valueOf(args[3].toUpperCase(Locale.ROOT));
        Path file=Path.of(args[2],type.name()+".mv.db");
        Storage storage=new Storage(file.toFile());
        try {
            Wallet wallet;
            if(action.equals("create")) {
                if(Files.exists(file)) throw new IllegalArgumentException("wallet exists");
                wallet=new Wallet("Quietproof disposable "+type);
                wallet.setPolicyType(PolicyType.SINGLE_HD);
                wallet.setScriptType(type);
                wallet.getKeystores().add(Keystore.fromSeed(new DeterministicSeed(new SecureRandom(),128,""),
                    PolicyType.SINGLE_HD,type.getDefaultDerivation()));
                wallet.setDefaultPolicy(Policy.getPolicy(PolicyType.SINGLE_HD,type,wallet.getKeystores(),1));
                storage.saveWallet(wallet);
            } else {
                if(!Files.isRegularFile(file)) throw new IllegalArgumentException("wallet missing");
                wallet=storage.loadUnencryptedWallet().getWallet();
                storage.restorePublicKeysFromSeed(wallet,null);
                if(wallet.getScriptType()!=type || wallet.getKeystores().size()!=1 || !wallet.isValid())
                    throw new IllegalArgumentException("unsupported wallet");
            }
            KeyPurpose purpose=switch(args[4]) {
                case "m/0/0" -> KeyPurpose.RECEIVE;
                case "m/1/0" -> KeyPurpose.CHANGE;
                default -> throw new IllegalArgumentException("unsupported owned key path");
            };
            WalletNode node=wallet.getNode(purpose).getChildren().stream()
                .filter(child -> child.getIndex()==0).findFirst().orElseThrow();
            String address=node.getAddress().toString();
            Map<String,Object> result=new LinkedHashMap<>();
            result.put("network",args[1]); result.put("scriptKind",args[3]);
            result.put("address",address);
            String derivation=wallet.getKeystores().getFirst().getKeyDerivation().getDerivationPath()
                +args[4].substring(1);
            result.put("derivation",derivation); result.put("keyPath",args[4]);
            if(action.equals("sign") || action.equals("verify")) {
                if(!address.equals(args[5])) throw new IllegalArgumentException("address mismatch");
                String format=args[6], text=message(args[7]);
                if(format.equals("bip322-full") || (format.equals("bip322-simple") && type==ScriptType.P2PKH)
                    || (!format.equals("bip322-simple") && type==ScriptType.P2TR))
                    throw new IllegalArgumentException("unsupported format for script kind");
                ECKey key=wallet.getKeystores().getFirst().getKey(node);
                String signature;
                if(action.equals("sign")) {
                    signature=format.equals("bip322-simple") ? Bip322.signMessageBip322(type,text,key)
                        : key.signMessage(text,format.equals("bip137") ? type : ScriptType.P2PKH);
                } else {
                    JsonObject input=JsonParser.parseString(Files.readString(Path.of(args[8]))).getAsJsonObject();
                    if(!input.get("format").getAsString().equals(format)
                        || !input.get("address").getAsString().equals(address)
                        || !input.get("network").getAsString().equals(args[1])
                        || !input.get("scriptKind").getAsString().equals(args[3])
                        || !input.get("derivation").getAsString().equals(derivation)
                        || (input.has("keyPath") && !input.get("keyPath").getAsString().equals(args[4])))
                        throw new IllegalArgumentException("signature metadata mismatch");
                    signature=input.get("signature").getAsString();
                }
                boolean verified;
                if(format.equals("bip322-simple")) {
                    if(!signature.startsWith("smp")) throw new IllegalArgumentException("expected bundled Simple prefix");
                    verified=Bip322.verifyMessageBip322(type,node.getAddress(),text,signature);
                } else {
                    byte[] compact=Base64.getDecoder().decode(signature);
                    if(compact.length!=65) throw new IllegalArgumentException("compact signature required");
                    int header=Byte.toUnsignedInt(compact[0]);
                    int low=format.equals("bip137") && type==ScriptType.P2WPKH ? 39 : 31;
                    if(header<low || header>low+3) throw new IllegalArgumentException("signature header mismatch");
                    ECKey recovered=ECKey.signedMessageToKey(text,signature,false);
                    verified=type.getAddress(PolicyType.SINGLE_HD,recovered).equals(node.getAddress());
                }
                if(!verified) throw new IllegalArgumentException("signature mismatch");
                result.put("format",format); result.put("verified",true);
                if(action.equals("sign")) result.put("signature",signature);
            }
            System.out.println(JSON.toJson(result));
        } finally {
            storage.closeAndWait();
        }
    }
}
