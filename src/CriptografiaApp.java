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
    public static void main(String[] args) {
        JFrame frame = new JFrame("Aplicativo de Criptografia");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();
        frame.add(panel);
        placeComponents(panel);

        frame.setSize(400, 300);
        frame.setVisible(true);

    }
    private static void placeComponents(JPanel panel) {
                                                            /*----------------Criaçao do layout----------------*/
        panel.setLayout(null);

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

        JLabel inputLabel1 = new JLabel("Enc.simétrica/assiétrica:");
        inputLabel1.setBounds(10, 150, 150, 25);
        panel.add(inputLabel1);

        JTextField inputTextField1 = new JTextField(20);
        inputTextField1.setBounds(150, 150, 200, 25);
        panel.add(inputTextField1);


        JLabel inputLabel2 = new JLabel("Hashing:");
        inputLabel2.setBounds(10, 200, 120, 25);
        panel.add(inputLabel2);

        JTextField inputTextField2 = new JTextField(20);
        inputTextField2.setBounds(150, 200, 200, 25);
        panel.add(inputTextField2);

        /*AdaptiveWidthTextField inputTextField1 = new AdaptiveWidthTextField(encryptedText);
        inputTextField1.setAlignmentX(30);
        inputTextField1.setAlignmentY(150);
        inputTextField1.getPreferredSize();
        panel.add(inputTextField1);*/


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
                String hashedText = hashText(inputText);
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
                    secretKey = generateSymmetricKey();
                    iv = generateIv();
                    encryptedText = encryptSymmetric(inputText, secretKey, iv);
                    System.out.println("Texto criptografado: " + encryptedText);
                    inputTextField1.setText(encryptedText);
                } else {
                    keyPair = generateAsymmetricKeyPair();
                    encryptedText = encryptAsymmetric(inputText, keyPair.getPublic());
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

                if (!isBase64(inputText)) {
                    System.out.println("Texto de entrada inválido. Certifique-se de fornecer um texto criptografado em Base64.");
                    return;
                }

                if (selectedCryptoType.equals("Simétrica")) {
                    if (secretKey == null || iv == null) {
                        System.out.println("Chave secreta ou vetor de inicialização não gerados.");
                    } else {
                        String decryptedText = decryptSymmetric(inputText, secretKey, iv);
                        System.out.println("Texto descriptografado: " + decryptedText);
                    }
                } else {
                    if (keyPair == null) {
                        System.out.println("Par de chaves não gerado.");
                    } else {
                        String decryptedText = decryptAsymmetric(inputText, keyPair.getPrivate());
                        System.out.println("Texto descriptografado: " + decryptedText);
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }


        });

    }
                                                /*----------------Métodos----------------*/
    private static String hashText(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    private static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static KeyPair generateAsymmetricKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static String encryptSymmetric(String plainText, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);

    }

    private static String decryptSymmetric(String cipherText, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted);
    }

    private static String encryptAsymmetric(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    private static boolean isBase64(String input) {
        String base64Regex = "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$";
        return input.matches(base64Regex);
    }

    private static String decryptAsymmetric(String cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted);
    }


}
