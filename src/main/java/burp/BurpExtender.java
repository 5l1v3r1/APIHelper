package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
//import burp.AESUtil;

import org.apache.commons.lang3.ArrayUtils;


public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener{
	
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
	
	private IContextMenuInvocation currentInvocation;
	private final String version;
	private final String name;
	
	public BurpExtender() {
		this.name = "Sign Me!";
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
        

	}


	
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
    	
    	if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
    			   invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE)
    	
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
		JMenu jMenu = new JMenu("Api Helper");
		
		jMenu.add(menuItem3); 
		jMenu.add(menuItem2);
		jMenu.add(menuItem);
		
		listMenuItems.add(jMenu);

        return listMenuItems;
    }
    
	public void actionPerformed(ActionEvent event) {
		String command = event.getActionCommand();
		if (command.equals("signme")) {
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
		        System.out.println("date: "+date);
		        // 发送body的数据长度
		        int length = body.length;
		        // 构造待加密sign字符串
		        String toSignStr = date+length+burp.AESUtil.head_pass;
		        // 对待加密sign字符串进行加密
		        String encryptedSign = burp.AESUtil.signBySHA256(toSignStr);
		        // 拼接owner组成完整签名字符串
		        String signStr = burp.AESUtil.owner+":"+encryptedSign;
		        
				headers.add("Sign:"+signStr);
				headers.add("Date:"+date);
				
				
				byte[] newRequest = helpers.buildHttpMessage(headers, body);
				selectedItems[0].setRequest(newRequest);
			} catch (Exception e) {
				
				stdout.println("Exception with custom context application");
				
			}
			
		}else if (command.equals("encme")){
			IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
			int[] selectedBounds = currentInvocation.getSelectionBounds();
			byte selectedInvocationContext = currentInvocation.getInvocationContext();
			
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
				s = burp.AESUtil.encrypt(helpers.bytesToString(selectedPortion), burp.AESUtil.KEY);
				} catch (Exception e) {
					stdout.println(e);
				}
				
				
				byte[] newRequest = ArrayUtils.addAll(preSelectedPortion, helpers.stringToBytes(s));
				newRequest = ArrayUtils.addAll(newRequest, postSelectedPortion);
				
				selectedItems[0].setRequest(newRequest);
			
			} catch (Exception e) {
				
				stdout.println("Exception with custom context application");
				
			}
		}else if (command.equals("decme")){
			IHttpRequestResponse[] selectedItems = currentInvocation.getSelectedMessages();
			int[] selectedBounds = currentInvocation.getSelectionBounds();
			byte selectedInvocationContext = currentInvocation.getInvocationContext();
			
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
					stdout.println("Data to decrypt: "+helpers.bytesToString(selectedPortion));
					s = burp.AESUtil.decrypt(helpers.bytesToString(selectedPortion), burp.AESUtil.KEY);
				} catch (Exception e) {
					stdout.println(e);
				}
			
				
				byte[] newRequest = ArrayUtils.addAll(preSelectedPortion, helpers.stringToBytes(s));
				newRequest = ArrayUtils.addAll(newRequest, postSelectedPortion);
				
				selectedItems[0].setRequest(newRequest);
			
			} catch (Exception e) {
				
				stdout.println("Exception with custom context application");
				
			}
		}
	}
	
	static String byteArrayToHexString(byte[] raw) {
        StringBuilder sb = new StringBuilder(2 + raw.length * 2);
        for (int i = 0; i < raw.length; i++) {
            sb.append(String.format("%02X", Integer.valueOf(raw[i] & 0xFF)));
        }
        return sb.toString();
    }

}
