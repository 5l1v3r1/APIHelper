package burp;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.PrintWriter;
import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
//import burp.AESUtil;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import org.apache.commons.lang3.ArrayUtils;


public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener, ITab{
	
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
	
	private IContextMenuInvocation currentInvocation;
	private final String version;
	private final String name;
	
	private JPanel panel;
    
    public final String TAB_NAME = "AES Config";
    private JTextField parameterAESkey;
    private JTextField parameterAESIV;
    private JLabel lblDescription;
    private JComboBox comboAESMode;
    private JLabel lbl3;
    private JCheckBox chckbxNewCheckBox;
    private JPanel panel_1;
    private JButton btnNewButton;
    private JTextArea textAreaPlaintext;
    private JTextArea textAreaCiphertext;
    private JButton btnNewButton_1;
    private JLabel lblPlaintext;
    private JLabel lblCiphertext;
    
    public Boolean isURLEncoded;
    public Boolean isAutoSign = false;
    
    private JLabel lbl4;
    private JComboBox comboEncoding;
    //private Bool autoSign;
	
	public BurpExtender() {
		this.name = "APIHelper";
		this.version = "0.1";
	}
	
	public void registerExtenderCallbacks (IBurpExtenderCallbacks c)
	{
        
        // Keep a reference to our callbacks object
        this.callbacks = c;
       
        // Obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // Set our extension name
        callbacks.setExtensionName(this.name + " " + this.version);
        
        //register to produce options for the context menu
        callbacks.registerContextMenuFactory(this);
        
        isURLEncoded = false;
        
        // Create UI
        this.addMenuTab();
        

	}
	
	/**
     * @wbp.parser.entryPoint
     * 
     * This code was built using Eclipse's WindowBuilder
     */
    public void buildUI() {
    	panel = new JPanel();
    	GridBagLayout gbl_panel = new GridBagLayout();
    	gbl_panel.columnWidths = new int[]{197, 400, 0};
    	gbl_panel.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0};
    	gbl_panel.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
    	gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
    	panel.setLayout(gbl_panel);
    	
    	lblDescription = new JLabel("APIHelper - AES");
    	lblDescription.setHorizontalAlignment(SwingConstants.LEFT);
    	lblDescription.setVerticalAlignment(SwingConstants.TOP);
    	GridBagConstraints gbc_lblDescription = new GridBagConstraints();
    	gbc_lblDescription.fill = GridBagConstraints.HORIZONTAL;
    	gbc_lblDescription.insets = new Insets(20, 20, 20, 20);
    	gbc_lblDescription.gridx = 1;
    	gbc_lblDescription.gridy = 0;
    	panel.add(lblDescription, gbc_lblDescription);
    	
    	JLabel lbl1 = new JLabel("AES key in hex format:");
    	lbl1.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl1 = new GridBagConstraints();
    	gbc_lbl1.anchor = GridBagConstraints.EAST;
    	gbc_lbl1.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl1.gridx = 0;
    	gbc_lbl1.gridy = 1;
    	panel.add(lbl1, gbc_lbl1);
    	
    	parameterAESkey = new JTextField();
    	parameterAESkey.setText("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    	GridBagConstraints gbc_parameterAESkey = new GridBagConstraints();
    	gbc_parameterAESkey.insets = new Insets(0, 0, 5, 0);
    	gbc_parameterAESkey.fill = GridBagConstraints.HORIZONTAL;
    	gbc_parameterAESkey.gridx = 1;
    	gbc_parameterAESkey.gridy = 1;
    	panel.add(parameterAESkey, gbc_parameterAESkey);
    	parameterAESkey.setColumns(10);
    	
    	JLabel lbl2 = new JLabel("IV in hex format:");
    	lbl2.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl2 = new GridBagConstraints();
    	gbc_lbl2.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl2.anchor = GridBagConstraints.EAST;
    	gbc_lbl2.gridx = 0;
    	gbc_lbl2.gridy = 2;
    	panel.add(lbl2, gbc_lbl2);
    	
    	parameterAESIV = new JTextField();
    	parameterAESIV.setText("abcdef1234567890abcdef1234567890");
    	parameterAESIV.setColumns(10);
    	GridBagConstraints gbc_parameterAESIV = new GridBagConstraints();
    	gbc_parameterAESIV.insets = new Insets(0, 0, 5, 0);
    	gbc_parameterAESIV.fill = GridBagConstraints.HORIZONTAL;
    	gbc_parameterAESIV.gridx = 1;
    	gbc_parameterAESIV.gridy = 2;
    	panel.add(parameterAESIV, gbc_parameterAESIV);
    	
//    	chckbxNewCheckBox = new JCheckBox("IV block in Ciphertext (not yet working)");
//    	chckbxNewCheckBox.setEnabled(false);
//    	GridBagConstraints gbc_chckbxNewCheckBox = new GridBagConstraints();
//    	gbc_chckbxNewCheckBox.fill = GridBagConstraints.HORIZONTAL;
//    	gbc_chckbxNewCheckBox.insets = new Insets(0, 0, 5, 0);
//    	gbc_chckbxNewCheckBox.gridx = 1;
//    	gbc_chckbxNewCheckBox.gridy = 3;
//    	panel.add(chckbxNewCheckBox, gbc_chckbxNewCheckBox);
    	
    	chckbxNewCheckBox = new JCheckBox("Enable auto SignMe while do EncryptMe using custom sign method");
    	chckbxNewCheckBox.setEnabled(true);
    	// set a property for later check whether this is enabled or not
    	
    	chckbxNewCheckBox.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent e){
                if(chckbxNewCheckBox.isSelected()) {
                	isAutoSign = true;
                }else {
                	isAutoSign = false;
                }
            }
        });
    	
    	GridBagConstraints autoSignBox = new GridBagConstraints();
    	autoSignBox.fill = GridBagConstraints.HORIZONTAL;
    	autoSignBox.insets = new Insets(0, 0, 5, 0);
    	autoSignBox.gridx = 1;
    	autoSignBox.gridy = 3;
    	panel.add(chckbxNewCheckBox, autoSignBox);
    	
    	

//    	comboAESMode = new JComboBox();
//    	comboAESMode.addPropertyChangeListener(new PropertyChangeListener() {
//    		public void propertyChange(PropertyChangeEvent arg0) {
//    			String cmode = (String)comboAESMode.getSelectedItem();
//    			if (cmode.contains("CBC")) {
//    				parameterAESIV.setEditable(true);
//    			} else {
//    				parameterAESIV.setEditable(false);
//    			}
//    		}
//    	});
    	
    	lbl4 = new JLabel("Ciphertext encoding:");
    	lbl4.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl4 = new GridBagConstraints();
    	gbc_lbl4.anchor = GridBagConstraints.EAST;
    	gbc_lbl4.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl4.gridx = 0;
    	gbc_lbl4.gridy = 4;
    	panel.add(lbl4, gbc_lbl4);
    	
    	comboEncoding = new JComboBox();
    	comboEncoding.setModel(new DefaultComboBoxModel(new String[] {"Base 64", "ASCII Hex"}));
    	comboEncoding.setSelectedIndex(0);
    	GridBagConstraints gbc_comboEncoding = new GridBagConstraints();
    	gbc_comboEncoding.insets = new Insets(0, 0, 5, 0);
    	gbc_comboEncoding.fill = GridBagConstraints.HORIZONTAL;
    	gbc_comboEncoding.gridx = 1;
    	gbc_comboEncoding.gridy = 4;
    	panel.add(comboEncoding, gbc_comboEncoding);
    	
    	lbl3 = new JLabel("AES Mode:");
    	lbl3.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl3 = new GridBagConstraints();
    	gbc_lbl3.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl3.anchor = GridBagConstraints.EAST;
    	gbc_lbl3.gridx = 0;
    	gbc_lbl3.gridy = 5;
    	panel.add(lbl3, gbc_lbl3);
    	
    	comboAESMode = new JComboBox();
    	comboAESMode.addPropertyChangeListener(new PropertyChangeListener() {
    		public void propertyChange(PropertyChangeEvent arg0) {
    			String cmode = (String)comboAESMode.getSelectedItem();
    			if (cmode.contains("CBC")) {
    				parameterAESIV.setEditable(true);
    			} else {
    				parameterAESIV.setEditable(false);
    			}
    		}
    	});
    	comboAESMode.setModel(new DefaultComboBoxModel(new String[] {"AES/CBC/NoPadding", "AES/CBC/PKCS5Padding", "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding", "AES"}));
    	comboAESMode.setSelectedIndex(1);
    	GridBagConstraints gbc_comboAESMode = new GridBagConstraints();
    	gbc_comboAESMode.insets = new Insets(0, 0, 5, 0);
    	gbc_comboAESMode.fill = GridBagConstraints.HORIZONTAL;
    	gbc_comboAESMode.gridx = 1;
    	gbc_comboAESMode.gridy = 5;
    	panel.add(comboAESMode, gbc_comboAESMode);
    	
    	panel_1 = new JPanel();
    	GridBagConstraints gbc_panel_1 = new GridBagConstraints();
    	gbc_panel_1.gridwidth = 2;
    	gbc_panel_1.fill = GridBagConstraints.BOTH;
    	gbc_panel_1.gridx = 0;
    	gbc_panel_1.gridy = 6;
    	panel.add(panel_1, gbc_panel_1);
    	GridBagLayout gbl_panel_1 = new GridBagLayout();
    	gbl_panel_1.columnWidths = new int[]{0, 0, 0, 0};
    	gbl_panel_1.rowHeights = new int[]{0, 0, 0, 0};
    	gbl_panel_1.columnWeights = new double[]{1.0, 0.0, 1.0, Double.MIN_VALUE};
    	gbl_panel_1.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
    	panel_1.setLayout(gbl_panel_1);
    	
    	lblPlaintext = new JLabel("Plaintext");
    	lblPlaintext.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lblPlaintext = new GridBagConstraints();
    	gbc_lblPlaintext.insets = new Insets(0, 0, 5, 5);
    	gbc_lblPlaintext.gridx = 0;
    	gbc_lblPlaintext.gridy = 0;
    	panel_1.add(lblPlaintext, gbc_lblPlaintext);
    	
    	lblCiphertext = new JLabel("Ciphertext");
    	lblCiphertext.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lblCiphertext = new GridBagConstraints();
    	gbc_lblCiphertext.insets = new Insets(0, 0, 5, 0);
    	gbc_lblCiphertext.gridx = 2;
    	gbc_lblCiphertext.gridy = 0;
    	panel_1.add(lblCiphertext, gbc_lblCiphertext);
    	
    	textAreaPlaintext = new JTextArea();
    	textAreaPlaintext.setLineWrap(true);
    	GridBagConstraints gbc_textAreaPlaintext = new GridBagConstraints();
    	gbc_textAreaPlaintext.gridheight = 2;
    	gbc_textAreaPlaintext.insets = new Insets(0, 0, 0, 5);
    	gbc_textAreaPlaintext.fill = GridBagConstraints.BOTH;
    	gbc_textAreaPlaintext.gridx = 0;
    	gbc_textAreaPlaintext.gridy = 1;
    	panel_1.add(textAreaPlaintext, gbc_textAreaPlaintext);
    	
    	btnNewButton = new JButton("Encrypt ->");
    	btnNewButton.addActionListener(new ActionListener() {
    		public void actionPerformed(ActionEvent arg0) {		
    	        try {
    	        		textAreaCiphertext.setText(encrypt(textAreaPlaintext.getText()));
    	        	
    	        } catch(Exception e) {
    	        	callbacks.issueAlert(e.toString());
    	        }
    			
    		}
    	});
    	GridBagConstraints gbc_btnNewButton = new GridBagConstraints();
    	gbc_btnNewButton.insets = new Insets(0, 0, 5, 5);
    	gbc_btnNewButton.gridx = 1;
    	gbc_btnNewButton.gridy = 1;
    	panel_1.add(btnNewButton, gbc_btnNewButton);
    	
    	textAreaCiphertext = new JTextArea();
    	textAreaCiphertext.setLineWrap(true);
    	GridBagConstraints gbc_textAreaCiphertext = new GridBagConstraints();
    	gbc_textAreaCiphertext.gridheight = 2;
    	gbc_textAreaCiphertext.fill = GridBagConstraints.BOTH;
    	gbc_textAreaCiphertext.gridx = 2;
    	gbc_textAreaCiphertext.gridy = 1;
    	panel_1.add(textAreaCiphertext, gbc_textAreaCiphertext);
    	
    	btnNewButton_1 = new JButton("<- Decrypt");
    	btnNewButton_1.addActionListener(new ActionListener() {
    		public void actionPerformed(ActionEvent arg0) {
    	        try {
    	        	textAreaPlaintext.setText(decrypt(textAreaCiphertext.getText()));
    	        } catch(Exception e) {
    	        	callbacks.issueAlert(e.toString());
    	        }
    		}
    	});
    	btnNewButton_1.setVerticalAlignment(SwingConstants.TOP);
    	GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
    	gbc_btnNewButton_1.anchor = GridBagConstraints.NORTH;
    	gbc_btnNewButton_1.insets = new Insets(0, 0, 0, 5);
    	gbc_btnNewButton_1.gridx = 1;
    	gbc_btnNewButton_1.gridy = 2;
    	panel_1.add(btnNewButton_1, gbc_btnNewButton_1);
    }
 
    public void addMenuTab() {
        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
            	buildUI();
            	callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    public String getTabCaption()
    {
        return "APIHelper - AES";
    }

    public Component getUiComponent()
    {
		return panel;
    }
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
	public static String byteArrayToHexString(byte[] b) {
		int len = b.length;
		String data = new String();
		for (int i = 0; i < len; i++){
			data += Integer.toHexString((b[i] >> 4) & 0xf);
			data += Integer.toHexString(b[i] & 0xf);
		}
		return data.toUpperCase();
	}
    
    public String encrypt(String plainText) throws Exception {
    	
    	byte[] keyValue= hexStringToByteArray(parameterAESkey.getText());
    	Key skeySpec = new SecretKeySpec(keyValue, "AES");
    	
    	byte[] iv = hexStringToByteArray(parameterAESIV.getText());
    	IvParameterSpec ivSpec = new IvParameterSpec(iv);

        String cmode = (String)comboAESMode.getSelectedItem();
        //stdout.println("cmode: "+cmode);
        Cipher cipher;
        
        if (cmode.equals("AES")) {
        	KeyGenerator kgen = KeyGenerator.getInstance("AES");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(keyValue);
			kgen.init(128, random);
			SecretKey secretKey = kgen.generateKey();
			byte[] enCodeFormat = secretKey.getEncoded();
//			 String x =  burp.SignUtil.parseByte2HexStr(enCodeFormat);
//	          stdout.println("x:"+x);
			SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, "AES");
			cipher = Cipher.getInstance("AES");// 创建密码器
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);// 初始化
        }else {
        	cipher = Cipher.getInstance((String)comboAESMode.getSelectedItem());
        	if (cmode.contains("CBC")) {
            	cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
            }else {
            	cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            }
        }

        byte[] encVal = cipher.doFinal(plainText.getBytes());

        String encryptedValue = new String(encVal, "UTF-8");
        
        switch (comboEncoding.getSelectedItem().toString()) {
    		case "Base 64":
    			encryptedValue = helpers.base64Encode(encVal);
    			break;
    		case "ASCII Hex":
    			encryptedValue = byteArrayToHexString(encVal);
    			break;
        }
        
        return encryptedValue;
    }
    
    public String decrypt(String ciphertext) throws Exception {

    	byte[] keyValue= hexStringToByteArray(parameterAESkey.getText());
    	Key skeySpec = new SecretKeySpec(keyValue, "AES");
    	byte[] iv = hexStringToByteArray(parameterAESIV.getText());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        String cmode = (String)comboAESMode.getSelectedItem();
        Cipher cipher;
        
        if (cmode.equals("AES")) {
        	KeyGenerator kgen = KeyGenerator.getInstance("AES");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(keyValue);
			kgen.init(128, random);
			SecretKey secretKey = kgen.generateKey();
			byte[] enCodeFormat = secretKey.getEncoded();
//			 String x =  burp.SignUtil.parseByte2HexStr(enCodeFormat);
//	          stdout.println("x:"+x);
			SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, "AES");
			cipher = Cipher.getInstance("AES");// 创建密码器
			cipher.init(Cipher.DECRYPT_MODE, keySpec);// 初始化
        }else {
        	cipher = Cipher.getInstance(cmode);
        	if (cmode.contains("CBC")) {
            	cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
            }else {
            	cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            }
        }
    	
        
        byte [] cipherbytes = ciphertext.getBytes();
        
        switch (comboEncoding.getSelectedItem().toString()) {
        	case "Base 64":
        		cipherbytes = helpers.base64Decode(ciphertext);
        		break;
    		case "ASCII Hex":
    			cipherbytes = hexStringToByteArray(ciphertext);
    			break;
        }
        
        byte[] original = cipher.doFinal(cipherbytes);
        return new String(original, "utf-8");
    	
    }

	
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
    	
		
    	
    	currentInvocation = invocation;

    	List<JMenuItem> listMenuItems = new ArrayList<JMenuItem>();
        // 菜单只在 REPEATER 工具的右键菜单中显示
		//子菜单
		JMenuItem menuItem;
		menuItem = new JMenuItem("SignMe!");  
		menuItem.setActionCommand("signme");
		menuItem.addActionListener(this);
		
		JMenuItem menuItem2;
		menuItem2 = new JMenuItem("EncryptMe");  
		menuItem2.setActionCommand("encme");
		menuItem2.addActionListener(this);
		
		JMenuItem menuItem3;
		menuItem3 = new JMenuItem("DecryptMe");  
		menuItem3.setActionCommand("decme");
		menuItem3.addActionListener(this);

		//父级菜单
		JMenu jMenu = new JMenu("APIHelper - AES");
		
		jMenu.add(menuItem3); 
		jMenu.add(menuItem2);
		jMenu.add(menuItem);
		
		listMenuItems.add(jMenu);

        return listMenuItems;
    }
	
	public void signMe() {
		stdout = new PrintWriter(callbacks.getStdout(), true);
		IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
		byte selectedInvocationContext = currentInvocation.getInvocationContext();
		
		try {
			
			byte[] selectedRequestOrResponse = null;
			if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
				selectedRequestOrResponse = selectedItems[0].getRequest();
			}
			
			IRequestInfo analyzeRequest = helpers.analyzeRequest(selectedRequestOrResponse);
			List<String> headers = analyzeRequest.getHeaders();
			
			// 删除已存在的sign与date头
			Iterator<String> it = headers.iterator();
			while(it.hasNext()){
			    String x = it.next();
			    if(x.startsWith("Date") || x.startsWith("Sign")){
			        it.remove();
			    }
			}
			
			String request = new String(selectedRequestOrResponse);
			byte[] body = request.substring(analyzeRequest.getBodyOffset()).getBytes();
			
			// 时间戳
	        Long date = new Date().getTime();
	        stdout.println("date: "+date);
	        // 发送body的数据长度
	        int length = body.length;
	        stdout.println("length: "+length);
	        // 构造待加密sign字符串
	        String toSignStr = date.toString()+String.valueOf(length)+burp.SignUtil.head_pass;
	        stdout.println("toSignStr: "+toSignStr);
	        // 对待加密sign字符串进行加密
	        String encryptedSign = burp.SignUtil.signBySHA256(toSignStr);
	        stdout.println("encryptedSign: "+encryptedSign);
	        // 拼接owner组成完整签名字符串
	        String signStr = burp.SignUtil.owner+":"+encryptedSign;
	        stdout.println("signStr: "+signStr);
	        
			headers.add("Sign:"+signStr);
			headers.add("Date:"+date);
			
			
			byte[] newRequest = helpers.buildHttpMessage(headers, body);
			selectedItems[0].setRequest(newRequest);
		} catch (Exception e) {
			
			stdout.println("Exception with custom context application");
			
		}
	}
    
	public void actionPerformed(ActionEvent event) {
		String command = event.getActionCommand();
		stdout = new PrintWriter(callbacks.getStdout(), true);
		IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
		byte selectedInvocationContext = currentInvocation.getInvocationContext();

		if (command.equals("signme")) {
			
			// The signme function is abstracted as another public mehod of class,
			// so that we can call it everytime together with Encrypt
			
			this.signMe();
			
			
			
		}else if (command.equals("encme")){
			int[] selectedBounds = currentInvocation.getSelectionBounds();
			
			try {
				
				byte[] selectedRequestOrResponse = null;
				if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
					selectedRequestOrResponse = selectedItems[0].getRequest();
				} else {
					selectedRequestOrResponse = selectedItems[0].getResponse();
				}
				
				byte[] preSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, 0, selectedBounds[0]);
				byte[] selectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[0], selectedBounds[1]);
				byte[] postSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[1], selectedRequestOrResponse.length);
				
				String s = "init data";
				
				try {
					stdout.println("Data to encrypt: "+helpers.bytesToString(selectedPortion));
					//s = burp.SignUtil.encrypt(helpers.bytesToString(selectedPortion), burp.SignUtil.KEY);
					s = this.encrypt(helpers.bytesToString(selectedPortion));//, burp.AESUtil.KEY);
				} catch (Exception e) {
					stdout.println(e);
				}
				
				
				byte[] newRequest = ArrayUtils.addAll(preSelectedPortion, helpers.stringToBytes(s));
				newRequest = ArrayUtils.addAll(newRequest, postSelectedPortion);
				
				selectedItems[0].setRequest(newRequest);
				// get autoSignBox is enabled or not
				if(this.isAutoSign) {
					stdout.println("AutoSign Enabled!");
					this.signMe();
				}
			
			} catch (Exception e) {
				
				stdout.println("Exception with custom context application");
				
			}
		}else if (command.equals("decme")){
			int[] selectedBounds = currentInvocation.getSelectionBounds();
			
			try {
				
				byte[] selectedRequestOrResponse = null;
				if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
					selectedRequestOrResponse = selectedItems[0].getRequest();
	//				} else {
	//					selectedRequestOrResponse = selectedItems[0].getResponse();
	//				}
					
					byte[] preSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, 0, selectedBounds[0]);
					byte[] selectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[0], selectedBounds[1]);
					byte[] postSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[1], selectedRequestOrResponse.length);
					
					String s = "init data";
	
					try {
						stdout.println("Data to decrypt: "+helpers.bytesToString(selectedPortion));
						//s = burp.SignUtil.decrypt(helpers.bytesToString(selectedPortion), burp.SignUtil.KEY);
						s = this.decrypt(helpers.bytesToString(selectedPortion));//, burp.AESUtil.KEY);
					} catch (Exception e) {
						stdout.println(e);
					}
				
					
					byte[] newRequest = ArrayUtils.addAll(preSelectedPortion, helpers.stringToBytes(s));
					newRequest = ArrayUtils.addAll(newRequest, postSelectedPortion);
					
					selectedItems[0].setRequest(newRequest);
				} else if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
						selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) { 
				//else if(selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
					stdout.println("Request Viewer");
					selectedRequestOrResponse = selectedItems[0].getResponse();
					byte[] preSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, 0, selectedBounds[0]);
					byte[] selectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[0], selectedBounds[1]);
					byte[] postSelectedPortion = Arrays.copyOfRange(selectedRequestOrResponse, selectedBounds[1], selectedRequestOrResponse.length);
					
					String s = "init data";
	
					try {
						stdout.println("Data to decrypt: "+helpers.bytesToString(selectedPortion));
						//s = burp.SignUtil.decrypt(helpers.bytesToString(selectedPortion), burp.SignUtil.KEY);
						s = this.decrypt(helpers.bytesToString(selectedPortion));//, burp.AESUtil.KEY);
					} catch (Exception e) {
						stdout.println(e);
					}
				
					
//					byte[] newResponse = ArrayUtils.addAll(preSelectedPortion, helpers.stringToBytes(s));
//					newResponse = ArrayUtils.addAll(newResponse, postSelectedPortion);
					String newRequestStr = s;
					
					SwingUtilities.invokeLater(new Runnable() {
						
			            @Override
			            public void run() {
			            	
			            	JTextArea ta = new JTextArea(30, 60);
			                ta.setText(newRequestStr);
			                ta.setWrapStyleWord(true);
			                ta.setLineWrap(true);
			                ta.setCaretPosition(0);
			                ta.setEditable(false);

			                JOptionPane.showMessageDialog(null, new JScrollPane(ta), "APIHelper Response Decrypt", JOptionPane.INFORMATION_MESSAGE);
						    
			            }
			            
					});
				}
			
			} catch (Exception e) {
				
				stdout.println("Exception with custom context application");
				
			}
		}
	}

}
