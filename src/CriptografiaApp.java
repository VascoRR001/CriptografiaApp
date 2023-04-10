import Methods.CryptographyMethods;

import java.security.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;

//import para o hashing
import javax.swing.JButton;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CriptografiaApp {
    private static SecretKey secretKey;
    private static IvParameterSpec iv;
    private static KeyPair keyPair;
    private static String encryptedText;
    private static JFrame frame;

    public static void main(String[] args) {
        frame = new JFrame("Aplicativo de Criptografia");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();
        frame.add(panel);
        placeComponents(panel);

        frame.setSize(450, 350);
        frame.setVisible(true);

    }

    private static void placeComponents(JPanel panel) {
        /*----------------Criaçao do layout----------------*/
        panel.setLayout(null);

        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("Arquivo");
        JMenuItem joinFilesMenuItem = new JMenuItem("Juntar arquivos");
        fileMenu.add(joinFilesMenuItem);
        menuBar.add(fileMenu);

        JMenu signatureMenu = new JMenu("Assinatura");
        JMenuItem signMessageMenuItem = new JMenuItem("Assinar mensagem");
        signatureMenu.add(signMessageMenuItem);
        menuBar.add(signatureMenu);

        frame.setJMenuBar(menuBar);
        JLabel label = new JLabel("Escolha o tipo de criptografia:");
        label.setBounds(10, 20, 200, 25);
        panel.add(label);

        JComboBox<String> cryptoTypeComboBox = new JComboBox<>(new String[]{"Simétrica", "Assimétrica"});
        cryptoTypeComboBox.setBounds(200, 20, 120, 25);
        panel.add(cryptoTypeComboBox);

        JLabel inputLabel = new JLabel("Texto:");
        inputLabel.setBounds(10, 60, 80, 25);
        panel.add(inputLabel);

        JTextField inputTextField = new JTextField(20);
        inputTextField.setBounds(70, 60, 165, 25);
        panel.add(inputTextField);

        JLabel inputLabel1 = new JLabel("Enc.simétrica/assimétrica:");
        inputLabel1.setBounds(10, 150, 160, 25);
        panel.add(inputLabel1);

        JTextField inputTextField1 = new JTextField(20);
        inputTextField1.setBounds(170, 150, 230, 25);
        panel.add(inputTextField1);


        JLabel inputLabel2 = new JLabel("Hashing:");
        inputLabel2.setBounds(10, 200, 120, 25);
        panel.add(inputLabel2);

        JTextField inputTextField2 = new JTextField(20);
        inputTextField2.setBounds(150, 200, 230, 25);
        panel.add(inputTextField2);

        JLabel inputLabel3 = new JLabel("Texto Desencriptado:");
        inputLabel3.setBounds(10, 250, 130, 25);
        panel.add(inputLabel3);

        JTextField inputTextField3 = new JTextField(20);
        inputTextField3.setBounds(150, 250, 230, 25);
        panel.add(inputTextField3);


        JButton encryptButton = new JButton("Criptografar");
        encryptButton.setBounds(10, 100, 120, 25);
        panel.add(encryptButton);

        JButton decryptButton = new JButton("Descriptografar");
        decryptButton.setBounds(240, 100, 130, 25);
        panel.add(decryptButton);

        JButton hashButton = new JButton("Hash");
        hashButton.setBounds(135, 100, 100, 25);
        panel.add(hashButton);

        /*----------------Eventos para butoes----------------*/
        hashButton.addActionListener(e -> {
            try {
                String inputText = inputTextField.getText();
                String hashedText = CryptographyMethods.hashText(inputText);
                System.out.println("Texto com hash: " + hashedText);
                inputTextField2.setText(hashedText);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });

        encryptButton.addActionListener(e -> {
            try {
                String inputText = inputTextField.getText();
                String selectedCryptoType = (String) cryptoTypeComboBox.getSelectedItem();

                if (selectedCryptoType.equals("Simétrica")) {
                    secretKey = CryptographyMethods.generateSymmetricKey();
                    iv = CryptographyMethods.generateIv();
                    encryptedText = CryptographyMethods.encryptSymmetric(inputText, secretKey, iv);
                    System.out.println("Texto criptografado: " + encryptedText);
                    inputTextField1.setText(encryptedText);
                } else {
                    keyPair = CryptographyMethods.generateAsymmetricKeyPair();
                    encryptedText = CryptographyMethods.encryptAsymmetric(inputText, keyPair.getPublic());
                    System.out.println("Texto criptografado: " + encryptedText);
                    inputTextField1.setText(encryptedText);
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });

        decryptButton.addActionListener(e -> {

            try {
                String inputText = encryptedText;
                String selectedCryptoType = (String) cryptoTypeComboBox.getSelectedItem();

                if (!CryptographyMethods.isBase64(inputText)) {
                    System.out.println("Texto de entrada inválido. Certifique-se de fornecer um texto criptografado em Base64.");
                    return;
                }

                if (selectedCryptoType.equals("Simétrica")) {
                    if (secretKey == null || iv == null) {
                        System.out.println("Chave secreta ou vetor de inicialização não gerados.");
                    } else {
                        String decryptedText = CryptographyMethods.decryptSymmetric(inputText, secretKey, iv);
                        System.out.println("Texto descriptografado: " + decryptedText);
                        inputTextField3.setText(decryptedText);
                    }
                } else {
                    if (keyPair == null) {
                        System.out.println("Par de chaves não gerado.");
                    } else {
                        String decryptedText = CryptographyMethods.decryptAsymmetric(inputText, keyPair.getPrivate());
                        System.out.println("Texto descriptografado: " + decryptedText);
                        inputTextField3.setText(decryptedText);
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }


        });

        signMessageMenuItem.addActionListener(e -> {
            try {
                // Gerar par de chaves RSA
                KeyPair keyPair = CryptographyMethods.generateKeyPair();
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();

                // Obter a mensagem do campo de texto e assiná-la
                String message = inputTextField.getText();
                byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                byte[] signatureBytes = CryptographyMethods.signData(messageBytes, privateKey);

                // Verificar a assinatura
                boolean isValid = CryptographyMethods.verifySignature(messageBytes, signatureBytes, publicKey);

                if (isValid) {
                    String signatureString = Base64.getEncoder().encodeToString(signatureBytes);
                    String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                    System.out.println("Assinatura: " + signatureString + "\nChave pública: " + publicKeyString);
                    JOptionPane.showMessageDialog(frame, "Mensagem assinada com sucesso!", "Sucesso", JOptionPane.INFORMATION_MESSAGE);
                    //outputTextArea.setText("Assinatura: " + signatureString + "\nChave pública: " + publicKeyString);
                } else {
                    System.out.println("A assinatura não pôde ser verificada.");
                    //outputTextArea.setText("A assinatura não pôde ser verificada.");
                }
            } catch (Exception ex) {
                ex.printStackTrace();
                JOptionPane.showMessageDialog(frame, "Erro ao assinar a mensagem.", "Erro", JOptionPane.ERROR_MESSAGE);
            }
        });


    }
}



