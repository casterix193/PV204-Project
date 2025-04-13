package ui;

import cardtools.*;
import applets.KeycardApplet;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.awt.event.*;

public class NostrUI extends JFrame {
    
    private static final Color DARK_BG = new Color(40, 40, 45);
    private static final Color DARKER_BG = new Color(30, 30, 35);
    private static final Color ACCENT = new Color(130, 105, 180);    
    private static final Color ACCENT_LIGHTER = new Color(160, 130, 210);
    private static final Color BUTTON_TEXT = new Color(20, 20, 25);    
    private static final Color TEXT_COLOR = new Color(230, 230, 230);
    private static final Color SECONDARY_TEXT = new Color(180, 180, 190);
    
    private JTextField pinField;
    private JTextArea contentArea;
    private JTextArea outputArea;
    private JButton connectButton;
    private JButton signButton;
    private JButton verifyButton;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    
    private CardManager cardManager;
    private NostrClient nostrClient;
    private boolean connected = false;
    
    public NostrUI() {
        setTitle("JavaCard Nostr");
        setSize(750, 650);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        setupUI();
        setupListeners();
        
        setLocationRelativeTo(null);
    }
    
    private void setupUI() {
        JPanel mainPanel = new JPanel(new BorderLayout(0, 0));
        mainPanel.setBackground(DARK_BG);
        
        JPanel headerPanel = createHeaderPanel();
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setBorder(null);
        splitPane.setDividerSize(5);
        splitPane.setDividerLocation(280);
        splitPane.setBackground(DARK_BG);
        splitPane.setForeground(ACCENT);
        
        JPanel contentPanel = createContentPanel();
        
        JPanel outputPanel = createOutputPanel();
        
        splitPane.setTopComponent(contentPanel);
        splitPane.setBottomComponent(outputPanel);
        
        JPanel statusPanel = createStatusPanel();
        
        mainPanel.add(headerPanel, BorderLayout.NORTH);
        mainPanel.add(splitPane, BorderLayout.CENTER);
        mainPanel.add(statusPanel, BorderLayout.SOUTH);
        
        setContentPane(mainPanel);
    }
    
    private JPanel createHeaderPanel() {
        JPanel headerPanel = new JPanel();
        headerPanel.setLayout(new BorderLayout());
        headerPanel.setBackground(DARKER_BG);
        headerPanel.setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));
        
        JLabel titleLabel = new JLabel("JavaCard Nostr");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        titleLabel.setForeground(ACCENT_LIGHTER);
        
        JPanel connectionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        connectionPanel.setBackground(DARKER_BG);
        
        JLabel pinLabel = new JLabel("PIN:");
        pinLabel.setForeground(TEXT_COLOR);
        pinLabel.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        
        pinField = new JTextField(6);
        pinField.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        pinField.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(ACCENT, 1),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        pinField.setBackground(DARK_BG);
        pinField.setForeground(TEXT_COLOR);
        pinField.setCaretColor(ACCENT);
        
        connectButton = createStyledButton("Connect");
        
        connectionPanel.add(pinLabel);
        connectionPanel.add(pinField);
        connectionPanel.add(connectButton);
        
        headerPanel.add(titleLabel, BorderLayout.WEST);
        headerPanel.add(connectionPanel, BorderLayout.EAST);
        
        return headerPanel;
    }
    
    private JPanel createContentPanel() {
        JPanel contentPanel = new JPanel(new BorderLayout(0, 10));
        contentPanel.setBackground(DARK_BG);
        contentPanel.setBorder(BorderFactory.createEmptyBorder(15, 20, 10, 20));
        
        JPanel inputPanel = new JPanel(new BorderLayout(0, 10));
        inputPanel.setBackground(DARK_BG);
        
        JLabel contentLabel = new JLabel("Message Content");
        contentLabel.setForeground(ACCENT_LIGHTER);
        contentLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        
        contentArea = new JTextArea(8, 40);
        contentArea.setLineWrap(true);
        contentArea.setWrapStyleWord(true);
        contentArea.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        contentArea.setBackground(DARKER_BG);
        contentArea.setForeground(TEXT_COLOR);
        contentArea.setCaretColor(ACCENT);
        contentArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JScrollPane contentScroll = new JScrollPane(contentArea);
        contentScroll.setBorder(BorderFactory.createLineBorder(ACCENT, 1));
        contentScroll.getVerticalScrollBar().setBackground(DARKER_BG);
        contentScroll.getVerticalScrollBar().setForeground(ACCENT);
        
        inputPanel.add(contentLabel, BorderLayout.NORTH);
        inputPanel.add(contentScroll, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonPanel.setBackground(DARK_BG);
        
        signButton = createStyledButton("Sign Message");
        verifyButton = createStyledButton("Verify");
        
        signButton.setEnabled(false);
        verifyButton.setEnabled(false);
        
        buttonPanel.add(signButton);
        buttonPanel.add(verifyButton);
        
        contentPanel.add(inputPanel, BorderLayout.CENTER);
        contentPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        return contentPanel;
    }
    
    private JPanel createOutputPanel() {
        JPanel outputPanel = new JPanel(new BorderLayout(0, 10));
        outputPanel.setBackground(DARK_BG);
        outputPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 15, 20));
        
        JPanel outputHeaderPanel = new JPanel(new BorderLayout());
        outputHeaderPanel.setBackground(DARK_BG);
        
        JLabel outputLabel = new JLabel("Signed Output");
        outputLabel.setForeground(ACCENT_LIGHTER);
        outputLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        
        JPanel outputActionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        outputActionPanel.setBackground(DARK_BG);
        
        JButton copyButton = createStyledButton("Copy");
        copyButton.addActionListener(e -> {
            if (!outputArea.getText().isEmpty()) {
                outputArea.selectAll();
                outputArea.copy();
                outputArea.setCaretPosition(outputArea.getText().length());
                statusLabel.setText("Output copied to clipboard");
            }
        });
        
        JButton clearButton = createStyledButton("Clear");
        clearButton.addActionListener(e -> outputArea.setText(""));
        
        outputActionPanel.add(clearButton);
        outputActionPanel.add(copyButton);
        
        outputHeaderPanel.add(outputLabel, BorderLayout.WEST);
        outputHeaderPanel.add(outputActionPanel, BorderLayout.EAST);
        
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setLineWrap(true);
        outputArea.setWrapStyleWord(true);
        outputArea.setFont(new Font("Consolas", Font.PLAIN, 13));
        outputArea.setBackground(DARKER_BG);
        outputArea.setForeground(TEXT_COLOR);
        outputArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JScrollPane outputScroll = new JScrollPane(outputArea);
        outputScroll.setBorder(BorderFactory.createLineBorder(ACCENT, 1));
        outputScroll.getVerticalScrollBar().setBackground(DARKER_BG);
        outputScroll.getVerticalScrollBar().setForeground(ACCENT);
        
        outputPanel.add(outputHeaderPanel, BorderLayout.NORTH);
        outputPanel.add(outputScroll, BorderLayout.CENTER);
        
        return outputPanel;
    }
    
    private JPanel createStatusPanel() {
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.setBackground(DARKER_BG);
        statusPanel.setBorder(BorderFactory.createEmptyBorder(5, 20, 5, 20));
        
        statusLabel = new JLabel("Ready");
        statusLabel.setForeground(SECONDARY_TEXT);
        
        progressBar = new JProgressBar();
        progressBar.setForeground(ACCENT);
        progressBar.setBackground(DARK_BG);
        progressBar.setPreferredSize(new Dimension(150, 10));
        progressBar.setStringPainted(false);
        progressBar.setBorderPainted(false);
        progressBar.setVisible(false);
        
        statusPanel.add(statusLabel, BorderLayout.WEST);
        statusPanel.add(progressBar, BorderLayout.EAST);
        
        return statusPanel;
    }
    
    private JButton createStyledButton(String text) {
        JButton button = new JButton(text);
        button.setFont(new Font("Segoe UI", Font.BOLD, 12));
        button.setForeground(BUTTON_TEXT);  
        button.setBackground(ACCENT);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        
        button.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                if (button.isEnabled()) {
                    button.setBackground(ACCENT_LIGHTER);
                }
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                if (button.isEnabled()) {
                    button.setBackground(ACCENT);
                }
            }
        });
        
        button.setBorder(BorderFactory.createEmptyBorder(7, 14, 7, 14));
        
        return button;
    }
    
    private void setupListeners() {
        connectButton.addActionListener(new ConnectButtonListener());
        signButton.addActionListener(new SignButtonListener());
        verifyButton.addActionListener(new VerifyButtonListener());
    }
    
    private class ConnectButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            new SwingWorker<Boolean, Void>() {
                @Override
                protected Boolean doInBackground() throws Exception {
                    try {
                        setStatus("Connecting to card simulator...", true);
                        
                        String pinStr = pinField.getText();
                        if (pinStr.length() != 6) {
                            appendOutput("Error: PIN must be 6 digits");
                            return false;
                        }
                        
                        byte[] pin = pinStr.getBytes();
                        
                        byte[] appletAIDBytes = {
                            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                            (byte) 0x62, (byte) 0x03, (byte) 0x01, (byte) 0x0C,
                            (byte) 0x06
                        };
                        
                        cardManager = new CardManager(true, appletAIDBytes);
                        RunConfig runConfig = RunConfig.getDefaultConfig();
                        runConfig.setAppletToSimulate(KeycardApplet.class);
                        runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
                        
                        boolean connected = cardManager.Connect(runConfig);
                        if (!connected) {
                            appendOutput("Failed to connect to card");
                            return false;
                        }
                        
                        appendOutput("Connected to card simulator");
                        
                        nostrClient = new NostrClient(cardManager);
                        boolean pinVerified = nostrClient.verifyPin(pin);
                        
                        if (!pinVerified) {
                            appendOutput("PIN verification failed");
                            return false;
                        }
                        
                        appendOutput("PIN verified successfully");
                        
                        boolean keyGenerated = nostrClient.generateKey();
                        if (!keyGenerated) {
                            appendOutput("Key generation failed");
                            return false;
                        }
                        
                        appendOutput("Key generated successfully");
                        appendOutput("Ready to sign messages");
                        
                        return true;
                    } catch (Exception ex) {
                        appendOutput("Error: " + ex.getMessage());
                        ex.printStackTrace();
                        return false;
                    }
                }
                
                @Override
                protected void done() {
                    try {
                        boolean success = get();
                        if (success) {
                            signButton.setEnabled(true);
                            verifyButton.setEnabled(true);
                            
                            connectButton.setText("Connected");
                            connectButton.setBackground(new Color(76, 175, 80));
                            connectButton.setEnabled(false);
                            
                            setStatus("Connected to card", false);
                            
                            connected = true;
                        } else {
                            setStatus("Connection failed", false);
                        }
                    } catch (Exception ex) {
                        appendOutput("Error: " + ex.getMessage());
                        setStatus("Error occurred", false);
                    }
                }
            }.execute();
        }
    }
    
    private class SignButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() throws Exception {
                    try {
                        if (!connected || nostrClient == null) {
                            return "Error: Not connected to card";
                        }
                        
                        String content = contentArea.getText();
                        if (content.isEmpty()) {
                            return "Error: Please enter content to sign";
                        }
                        
                        setStatus("Creating and signing Nostr event...", true);
                        
                        NostrEvent event = new NostrEvent(1, content);
                        boolean signed = event.sign(nostrClient);
                        
                        if (!signed) {
                            return "Error: Failed to sign event";
                        }
                        
                        return event.toJson();
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        return "Error: " + ex.getMessage();
                    }
                }
                
                @Override
                protected void done() {
                    try {
                        String result = get();
                        if (result.startsWith("Error:")) {
                            appendOutput(result);
                            setStatus("Signing failed", false);
                        } else {
                            appendOutput("Event signed successfully\n");
                            appendOutput(result);
                            setStatus("Event signed successfully", false);
                        }
                    } catch (Exception ex) {
                        appendOutput("Error: " + ex.getMessage());
                        setStatus("Error occurred", false);
                    }
                }
            }.execute();
        }
    }
    
    private class VerifyButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            appendOutput("\n=== VERIFICATION INSTRUCTIONS ===");
            appendOutput("To verify your signed event:");
            appendOutput("1. Copy the JSON output above");
            appendOutput("2. Visit https://nostdav.com or any Nostr relay tester");
            appendOutput("3. Paste the JSON and verify the signature");
            appendOutput("===============================");
        }
    }
    
    private void appendOutput(String text) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append(text + "\n");
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }
    
    private void setStatus(String status, boolean inProgress) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText(status);
            progressBar.setVisible(inProgress);
            if (inProgress) {
                progressBar.setIndeterminate(true);
            } else {
                progressBar.setIndeterminate(false);
            }
        });
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                e.printStackTrace();
            }
            new NostrUI().setVisible(true);
        });
    }
}