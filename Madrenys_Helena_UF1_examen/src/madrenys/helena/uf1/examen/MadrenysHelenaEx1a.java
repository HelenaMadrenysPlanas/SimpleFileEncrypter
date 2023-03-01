package madrenys.helena.uf1.examen;

//@author: Helena Madrenys Planas

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MadrenysHelenaEx1a {
	public static void main(String[] args) throws IOException {
		//Creem el fitxer---------------------------------------------------
		//Creem el missatge
		String missatge = "Helena Madrenys Planas";
		System.out.println("El missatge és: " + missatge);

		//Creem la contrassenya
		String contrassenya = "333";
		System.out.println("La contrassenya serà: " + contrassenya);

		//Generar les claus simètriques a partir de contrassenya
		SecretKey clauS = generarClauContrassenya(contrassenya, "SHA-256", "AES", 128);
		
		//Encriptem el missatge
		String encriptat = encriptar(clauS, missatge);
		System.out.println("Al fitxer s'hi ha escrit:" + encriptat);
		
		//Posem el missatge en un fitxer
		FileWriter myWriter = new FileWriter("missatge.dat");
		myWriter.write(encriptat);
		myWriter.close();
		System.out.println("S'ha omplert el fitxer correctament.");

		//Llegim el fitxer----------------------------------------------------
		File fitxer = new File("missatge.dat");
		Scanner scFitxer = new Scanner(fitxer);
		String contXifrat = "";
		while (scFitxer.hasNextLine()) {
			contXifrat += scFitxer.nextLine();
		}
		scFitxer.close();
		System.out.println("El contingut del fitxer xifrat és:" + contXifrat);
		
		//Demanem la contrassenya i creem la clau
		System.out.println("Escriu la contrassenya del fitxer:");
		Scanner sc = new Scanner(System.in);
		String decryptPsswd = sc.nextLine();
		sc.close();
		SecretKey decryptKey = generarClauContrassenya(decryptPsswd, "SHA-256", "AES", 128);
		//Desxifrem i mostrem
		try {
			String contDesxifrat = desencriptar(decryptKey, contXifrat);
			System.out.println("El contingut desxifrat és: " + contDesxifrat);
		}catch (Exception e)
		{
			System.out.println("Clau incorrecte.");
		}
		
		//Text interceptat: wgxX/Dzp8qtHRI7KZE/7KucmtNIAqAzoxWTSoJw1AQA=
		//Contrassenya: 333
	}
	//Funció generar clau a partir de contrassenya
	public static SecretKey generarClauContrassenya(String text, String alHash, String algorisme, int keySize)
	{
		SecretKey sKey = null;
		try
		{
			byte[] data = text.getBytes("UTF-8");
	        MessageDigest md = MessageDigest.getInstance(alHash);
	        byte[] hash = md.digest(data);
	        byte[] key = Arrays.copyOf(hash, keySize/8);
	        sKey = new SecretKeySpec(key, algorisme);
		}
		catch (Exception e)
		{
			System.err.println("Hi ha hagut un error " + e);
			return null;
		}
		return sKey;
	}
	//Funció per encriptar--------------------------------------------------
	public static String encriptar(SecretKey sKey, String missatge) {
		//Creem l'array on hi col·locarem les dades encriptades
		byte[] encriptat = null;
		try {
			//Creem un objecte cipher amb els paràmetres desitjats
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			
			//L'inicialitzem amb el mode d'encriptació i la clau generada anteriorment
			cipher.init(Cipher.ENCRYPT_MODE, sKey);
			
			//Encriptem
			encriptat = cipher.doFinal(missatge.getBytes());
		} catch (Exception ex) {
		System.err.println("Error xifrant les dades.");
		}
		
		//Passem el missatge de byte[] a String i el retornem
		String txtreturn = Base64.getEncoder().encodeToString(encriptat);
		return txtreturn;
	}
	//Funció per desencriptar--------------------------------------------------
	public static String desencriptar(SecretKey sKey, String missatge) {
		//Creem l'array on hi col·locarem les dades desencriptades
		byte[] desencriptat = null;
		try {
			//Creem un objecte cipher amb els paràmetres desitjats
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			
			//L'inicialitzem amb el mode de desenccriptació i la clau generada anteriorment
			cipher.init(Cipher.DECRYPT_MODE, sKey);
			
			//Desencriptem
			desencriptat = cipher.doFinal(Base64.getDecoder().decode(missatge));
		} catch (Exception ex) {
			System.out.println("Error desxifrant les dades.");
		}
		
		//Passem el missatge de byte[] a String i el retornem
		String txtreturn = new String(desencriptat);
		return txtreturn;
	}
}
