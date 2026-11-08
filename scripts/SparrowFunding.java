// Offline disposable P2PKH transfer adapter over installed Sparrow/Drongo.
// This separate entry point does not change the message signer's contract.
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.*;
import com.sparrowwallet.drongo.wallet.*;
import com.sparrowwallet.sparrow.io.Storage;

public class SparrowFunding {
    private static final HexFormat HEX = HexFormat.of();
    private static void check(boolean value) {
        if(!value) throw new IllegalArgumentException("disposable transfer constraint");
    }
    private static WalletNode node(Wallet wallet, KeyPurpose purpose) {
        return wallet.getNode(purpose).getChildren().stream()
            .filter(child -> child.getIndex()==0).findFirst().orElseThrow();
    }
    public static void main(String[] args) {
        try {
            run(args);
            System.exit(0);
        } catch(Exception error) {
            System.err.println("Sparrow funding adapter rejected operation; details withheld");
            System.exit(1);
        }
    }
    private static void run(String[] args) throws Exception {
        check(args.length==2 || args.length==3);
        check(args[0].equals("describe") || args[0].equals("prepare"));
        Network.set(Network.SIGNET);
        Storage storage = new Storage(Path.of(args[1],"P2PKH.mv.db").toFile());
        try {
            Wallet wallet=storage.loadUnencryptedWallet().getWallet();
            storage.restorePublicKeysFromSeed(wallet,null);
            check(wallet.isValid() && wallet.getScriptType()==ScriptType.P2PKH
                && wallet.getKeystores().size()==1 && wallet.getPolicyType()==PolicyType.SINGLE_HD);
            WalletNode receive=node(wallet,KeyPurpose.RECEIVE), change=node(wallet,KeyPurpose.CHANGE);
            Map<String,Object> result=new LinkedHashMap<>();
            result.put("network","signet");
            result.put("sourceAddress",receive.getAddress().toString());
            result.put("sourceScript",receive.getOutputScript().getProgramAsHex());
            result.put("changeAddress",change.getAddress().toString());
            result.put("changeScript",change.getOutputScript().getProgramAsHex());
            result.put("sourceDerivation",receive.getDerivationPath());
            result.put("changeDerivation",change.getDerivationPath());
            if(args[0].equals("prepare")) {
                check(args.length==3);
                JsonObject intent=JsonParser.parseString(Files.readString(Path.of(args[2]))).getAsJsonObject();
                check(intent.get("network").getAsString().equals("signet"));
                check(intent.get("sourceAddress").getAsString().equals(result.get("sourceAddress")));
                check(intent.get("changeAddress").getAsString().equals(result.get("changeAddress")));
                check(intent.get("changeScript").getAsString().equals(result.get("changeScript")));
                Transaction parent=new Transaction(HEX.parseHex(intent.get("sourceTransaction").getAsString()));
                check(parent.getTxId().toString().equals(intent.get("sourceTxid").getAsString()));
                int vout=intent.get("sourceVout").getAsInt();
                check(vout>=0 && vout<parent.getOutputs().size());
                TransactionOutput source=parent.getOutputs().get(vout);
                check(source.getScript().equals(receive.getOutputScript()));
                long value=source.getValue(), amount=intent.get("amountSats").getAsLong();
                long fee=intent.get("feeSats").getAsLong(), changeValue=value-amount-fee;
                check(value==intent.get("sourceValueSats").getAsLong());
                check(amount==3000 && fee>0 && fee<=500 && amount+fee<=3500 && changeValue>=546);
                Address destination=Address.fromString(Network.SIGNET,intent.get("destinationAddress").getAsString());
                check(destination.getScriptType()==ScriptType.P2PKH);
                check(destination.getOutputScript().getProgramAsHex().equals(intent.get("destinationScript").getAsString()));
                check(!destination.equals(receive.getAddress()) && !destination.equals(change.getAddress()));
                Transaction tx=new Transaction(); tx.setVersion(2); tx.setLocktime(0);
                TransactionInput input=tx.addInput(parent.getTxId(),vout,new Script(new byte[0]));
                input.setSequenceNumber(0xffffffffL);
                tx.addOutput(amount,destination); tx.addOutput(changeValue,change.getAddress());
                ECKey key=wallet.getKeystores().getFirst().getKey(receive);
                check(key.hasPrivKey() && key.isCompressed());
                Sha256Hash hash=tx.hashForLegacySignature(0,source.getScript(),SigHash.ALL);
                TransactionSignature signature=key.sign(hash,SigHash.ALL,TransactionSignature.Type.ECDSA);
                check(key.verify(hash,signature));
                input.setScriptBytes(ScriptType.P2PKH.getScriptSig(PolicyType.SINGLE_HD,source.getScript(),key,signature).getProgram());
                tx.verify();
                result.put("txid",tx.getTxId().toString());
                result.put("rawTransaction",HEX.formatHex(tx.bitcoinSerialize()));
                result.put("feeSats",fee); result.put("changeSats",changeValue);
                result.put("signatureVerified",true);
            }
            System.out.println(new Gson().toJson(result));
        } finally { storage.closeAndWait(); }
    }
}
