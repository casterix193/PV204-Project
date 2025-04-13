package cardtools;

import java.security.MessageDigest;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;

public class NostrEvent {
    private long createdAt;
    private int kind;
    private List<List<String>> tags;
    private String content;
    private String pubkey;
    private String id;
    private String sig;
    
    public NostrEvent(int kind, String content) {
        this.createdAt = System.currentTimeMillis() / 1000; // Unix timestamp in seconds
        this.kind = kind;
        this.content = content;
        this.tags = new ArrayList<>();
    }
    
    public NostrEvent(long createdAt, int kind, String content) {
        this.createdAt = createdAt;
        this.kind = kind;
        this.content = content;
        this.tags = new ArrayList<>();
    }
    
    public void addTag(List<String> tag) {
        tags.add(tag);
    }
    
    public void addEventTag(String eventId) {
        List<String> tag = new ArrayList<>();
        tag.add("e");
        tag.add(eventId);
        tags.add(tag);
    }
    
    public void addPubkeyTag(String pubkey) {
        List<String> tag = new ArrayList<>();
        tag.add("p");
        tag.add(pubkey);
        tags.add(tag);
    }
   
    public String getCanonicalForm() {
        StringBuilder sb = new StringBuilder();
        sb.append("[0,");
        
        if (pubkey != null) {
            sb.append("\"").append(pubkey).append("\",");
        } else {
            sb.append("\"\",");
        }
        
        sb.append(createdAt).append(",");
        sb.append(kind).append(",");
        
        // Serialize tags as a JSON array of arrays
        sb.append("[");
        for (int i = 0; i < tags.size(); i++) {
            List<String> tag = tags.get(i);
            sb.append("[");
            for (int j = 0; j < tag.size(); j++) {
                sb.append("\"").append(escapeJson(tag.get(j))).append("\"");
                if (j < tag.size() - 1) {
                    sb.append(",");
                }
            }
            sb.append("]");
            if (i < tags.size() - 1) {
                sb.append(",");
            }
        }
        sb.append("],");
        
        sb.append("\"").append(escapeJson(content)).append("\"");
        sb.append("]");
        
        return sb.toString();
    }
    
    private String escapeJson(String input) {
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t")
                    .replace("\b", "\\b")
                    .replace("\f", "\\f");
    }
    
    public byte[] getEventHash() throws Exception {
        String canonicalForm = getCanonicalForm();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(canonicalForm.getBytes("UTF-8"));
    }
    
    public boolean sign(NostrClient client) throws Exception {
        // Compute the event hash
        byte[] eventHash = getEventHash();
        
        // Sign the hash using the client
        NostrClient.NostrSignature signature = client.signEvent(getCanonicalForm());
        
        // Set the pubkey, id, and sig fields
        this.pubkey = signature.getPublicKeyHex();
        this.id = bytesToHex(eventHash);
        this.sig = signature.getSignatureHex();
        
        return true;
    }
        
    public boolean signWithPath(NostrClient client, byte[] keyPath, boolean makeCurrent) throws Exception {
        // Sign the hash using the client with the specified derivation path
        NostrClient.NostrSignature signature = client.signEventWithPath(getCanonicalForm(), keyPath, makeCurrent);
        
        // Set the pubkey, id, and sig fields
        this.pubkey = signature.getPublicKeyHex();
        this.id = bytesToHex(getEventHash());
        this.sig = signature.getSignatureHex();
        
        return true;
    }
    
    // Returns the event as a JSON object string representation.
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        
        sb.append("\"id\":\"").append(id).append("\",");
        sb.append("\"pubkey\":\"").append(pubkey).append("\",");
        sb.append("\"created_at\":").append(createdAt).append(",");
        sb.append("\"kind\":").append(kind).append(",");
        
        // Serialize tags
        sb.append("\"tags\":[");
        for (int i = 0; i < tags.size(); i++) {
            List<String> tag = tags.get(i);
            sb.append("[");
            for (int j = 0; j < tag.size(); j++) {
                sb.append("\"").append(escapeJson(tag.get(j))).append("\"");
                if (j < tag.size() - 1) {
                    sb.append(",");
                }
            }
            sb.append("]");
            if (i < tags.size() - 1) {
                sb.append(",");
            }
        }
        sb.append("],");
        
        sb.append("\"content\":\"").append(escapeJson(content)).append("\",");
        sb.append("\"sig\":\"").append(sig).append("\"");
        
        sb.append("}");
        
        return sb.toString();
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
    
    // Getters and setters
    public long getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }
    
    public int getKind() {
        return kind;
    }
    
    public void setKind(int kind) {
        this.kind = kind;
    }
    
    public List<List<String>> getTags() {
        return tags;
    }
    
    public void setTags(List<List<String>> tags) {
        this.tags = tags;
    }
    
    public String getContent() {
        return content;
    }
    
    public void setContent(String content) {
        this.content = content;
    }
    
    public String getPubkey() {
        return pubkey;
    }
    
    public String getId() {
        return id;
    }
    
    public String getSig() {
        return sig;
    }
}