package criptografia;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;

/**
   @date   03 out 2022
   @author Jonas Fernando Schuh
           Iago Tambosi
           Gabriel Kresin
  
   Trabalho 
   Construa um programa que implemente o algoritmo de criptografia AES. 
   O programa deve atender aos seguintes requisitos:
x  a) Permitir que o usuário informe um arquivo a ser criptografado. O programa deverá suportar qualquer arquivo  
    (texto ou binário); 
x  b) Permitir que o usuário possa informar o nome do arquivo de destino a ser gerado;
   c) Permitir que o usuário forneça a chave de criptografia. Deve ser um campo texto em que possa ser fornecido os
   valores dos bytes da chave, separando os bytes por vírgula. Por exemplo: este é um texto que deve ser possível 
   fornecer para indicar os bytes da chave: ?20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248?;
   d) Implementar o modo de operação ECB e tamanho de chave de 128 bits;
   e) Implementar o modo de preenchimento PKCS#7;
   f) A solução não pode ser cópia de outros autores e deve utilizar a abordagem vista em sala de aula
  
  */

public class Trabalho {
    
public static final int[][] sbox = {        
        //  0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},  // 0
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},  // 1
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},  // 2
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},  // 3
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},  // 4
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},  // 5
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},  // 6
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},  // 7
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},  // 8
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},  // 9
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},  // A
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},  // B
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},  // C
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},  // D
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},  // E
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}}; // F
   
    public static final int[] sRoundKey = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
   
    static Integer[][] matrizChaveInt = new Integer[4][4];
    static String[][] matrizChaveHex = new String[4][4];
   
    public static void popularMatrizChave(String chave) {
        String[] matrizChave = chave.split(",");
        int cont = 0;
        for (int col = 0; col < matrizChaveInt.length; col++) {
           for (int lin = 0; lin < matrizChaveInt.length; lin++) {
                Integer valor = Integer.parseInt(matrizChave[cont]);
                //System.out.println(lin + "" + col + " - " + valor);
                matrizChaveInt[col][lin] = valor;
                matrizChaveHex[col][lin] = Integer.toHexString(valor);
                cont++;
           }
       }
    }
   
    public static void imprimeMatriz(Integer[][] matriz) {
        System.out.println("\nMatriz integer");
        for (int col = 0; col < matriz.length; col++) {
           for (int lin = 0; lin < matriz.length; lin++) {
                System.out.printf("%3d   ", matriz[lin][col]);
                if (lin == 3) {
                    System.out.print("\n");
                }
           }
       }
    }
   
    public static void imprimeMatrizHex(String[][] matriz) {
        System.out.println("\nMatriz hex");
        for (int col = 0; col < matriz.length; col++) {
           for (int lin = 0; lin < matriz.length; lin++) {
                System.out.printf("%3s   ", matriz[lin][col]);
                if (lin == 3) {
                    System.out.print("\n");
                }
           }
       }
       System.out.println("\n");
    }
   
    public static String[] converteChaveString(String chave, Boolean isHex) {
        String[] archave = chave.split(",");
        String[] arTemp = new String[archave.length];
        for (int i = 0; i < archave.length; i++) {
            Integer valor = Byte.toUnsignedInt(archave[i].getBytes()[0]);            
            if (isHex) {
                arTemp[i] = Integer.toHexString(valor);
            } else {
                arTemp[i] = valor.toString();
            }
        }
        return arTemp;
    }    
   
    public static String converteChaveStringToByte(String chave, Boolean isHex) {
        String[] archave = chave.split(",");
        String sTemp = "";
        for (int i = 0; i < archave.length; i++) {
            Integer valor = Byte.toUnsignedInt(archave[i].getBytes()[0]);            
            if (isHex) {
                sTemp += Integer.toHexString(valor) + ",";
            } else {
                sTemp += valor.toString() + ",";
            }
        }
        sTemp = sTemp.substring(0, sTemp.length()-1);
        return sTemp;
    }    
   
    public static void insereLog(String mensagem) {
        Date dataHoraAtual = new Date();
        String hora = new SimpleDateFormat("HH:mm:ss").format(dataHoraAtual);
        //System.out.println(hora + ": " + mensagem);
        System.out.println(mensagem);
    }

    public static String[] extrairColunaArray(String[][] ar, Integer coluna) {
        String[] arTemp = new String[ar[0].length];
        for (int i = 0; i < arTemp.length; i++) {
            arTemp[i] = ar[coluna][i];
        }
        return arTemp;
    }
   
    public static void imprimeColunaVetor(String [] arColuna) {        
        for (int i = 0; i < arColuna.length; i++) {
            System.out.println(arColuna[i]);
        }
    }    
   
    public static String[] parte2_rotacionaColunaVetor_RotWord(String[] vetor) {
        int tamanho = vetor.length;
        String[] arTemp = new String[tamanho];
       
        for (int i = 0; i < vetor.length; i++) {
            if (i+1 < vetor.length) {
                arTemp[i] = vetor[i+1];
            } else {
                arTemp[i] = vetor[0];
            }
        }
        return arTemp;
    }
   
    public static String substituiSbox(String letra) {

        Character primeira = letra.charAt(0);
        Character segunda;        
        if (letra.length() == 1) {
            segunda = '0';
        } else {
            segunda = letra.charAt(1);        
        }
        Integer linha = hexToIntegerSBox(primeira);
        Integer coluna = hexToIntegerSBox(segunda);
       
        Integer valor = sbox[linha][coluna];
       
        return Integer.toHexString(valor);
    }
   
    public static Integer hexToIntegerSBox(Character c) {
       
        if (Character.isDigit(c)) {
            return Integer.parseInt(c.toString());
        } else if (c.toString().equalsIgnoreCase("a")) {
            return 10;    
        } else if (c.toString().equalsIgnoreCase("b")) {
            return 11;    
        } else if (c.toString().equalsIgnoreCase("c")) {
            return 12;    
        } else if (c.toString().equalsIgnoreCase("d")) {
            return 13;    
        } else if (c.toString().equalsIgnoreCase("e")) {
            return 14;    
        } else if (c.toString().equalsIgnoreCase("f")) {
            return 15;                
        } else {          
            return null;
        }
    }
   
    public static String getRoundKey(Integer value) {
        return Integer.toHexString(sRoundKey[value]);
    }
   
    public static String[] parte3_substituiPalavra_SubstWord(String[] vetor) {
        String[] arTemp = new String[vetor.length];
        for (int i = 0; i < vetor.length; i++) {            
            arTemp[i] = substituiSbox(vetor[i]);
        }
        return arTemp;
    }
   
    public static String[] parte4_getRoundConstant(Integer roundKey) {
        String[] vetor = new String[4];
        vetor[0] = getRoundKey(roundKey);
        vetor[1] = "0";
        vetor[2] = "0";                
        vetor[3] = "0";                
        return vetor;
    }
   
    public static String[] parte5_XorRoundConstant(String[] colunaSubstituida, String[] colunaRoundConstant) {
        String[] arTemp = new String[colunaSubstituida.length];
       
        arTemp[0] = XOR2Hex(colunaSubstituida[0], colunaRoundConstant[0]);
        arTemp[1] = XOR2Hex(colunaSubstituida[1], colunaRoundConstant[1]);        
        arTemp[2] = XOR2Hex(colunaSubstituida[2], colunaRoundConstant[2]);        
        arTemp[3] = XOR2Hex(colunaSubstituida[3], colunaRoundConstant[3]);        
       
        return arTemp;
    }
   
    public static Integer HexToInt(String value) {
        return Integer.parseInt(value, 16);
    }
   
    public static String XOR2Hex(String value1, String value2) {
        int n1 = HexToInt(value1);
        int n2 = HexToInt(value2);
        int n3 = n1 ^ n2;            
        return Integer.toHexString(n3);
    }
   
    public static String[] parte6_XORRoundKeyAnterior(Integer colunaAtual, String[] colunaXorRoundConstant) {
        String[] coluna1Anterior = extrairColunaArray(matrizChaveHex, colunaAtual-1-4);
        String[] arTemp = new String[colunaXorRoundConstant.length];
       
        arTemp[0] = XOR2Hex(coluna1Anterior[0], colunaXorRoundConstant[0]);
        arTemp[1] = XOR2Hex(coluna1Anterior[1], colunaXorRoundConstant[1]);
        arTemp[2] = XOR2Hex(coluna1Anterior[2], colunaXorRoundConstant[2]);
        arTemp[3] = XOR2Hex(coluna1Anterior[3], colunaXorRoundConstant[3]);      
       
        return arTemp;
    }
   
    public static void insereColunaMatriz(String[][] matriz, String[] vetor, Integer coluna) {        
        for (int i = 0; i < vetor.length; i++) {
            matriz[coluna][i] = vetor[i];
        }
    }        

    Scanner scanner = new Scanner(System.in);
    String caminhoArquivoEntrada;
    String caminhoArquivoDestino;
    String conteudo = "teste";
    String chave;
    
    public Trabalho() {
        System.out.println("Inicializando classe trabalho");
        
    }

    public void executarLeituraDadosIniciais() {
        System.out.println("Informe o caminho do arquivo a ser criptografado. - \n"
                + "(Enter padrao) -> c:\\temp\\exemplo.txt");
        caminhoArquivoEntrada = scanner.nextLine().toUpperCase();
        if (caminhoArquivoEntrada.equalsIgnoreCase("")) {
            caminhoArquivoEntrada = "c:\\temp\\exemplo.txt";
        }
        
        System.out.println("Informe o caminho do arquivo de destino. \n"
                + "(Enter padrao) -> c:\\temp\\destino.txt");
        caminhoArquivoDestino = scanner.nextLine().toUpperCase();
        if (caminhoArquivoDestino.equalsIgnoreCase("")) {
            caminhoArquivoDestino = "c:\\temp\\destino.txt";
        }
        
        System.out.println("Forneça a chave de criptografia. Valores dos bytes da chave, separando os bytes por vírgula.\n"
                + "(Enter padrao) -> 20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248 ");
        chave = scanner.nextLine().toUpperCase();
        if (chave.equalsIgnoreCase("")) {
            chave = "20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248";
        }
    }
    
    public void lerArquivo() {
        try {
            // tratar para ler byte a byte 
            InputStream entrada = new FileInputStream(caminhoArquivoEntrada);
            int umByte = entrada.read();
     
            while(umByte != -1){
                System.out.print((char)umByte);
                try {
                    umByte = entrada.read();
                } catch (IOException ex) {
                    System.out.println(ex.getMessage());
                }
            }    
        } catch (IOException ex) {
            System.out.println("ERRO: " + ex.getMessage());
        }
    }
    
    public void escreverArquivo() {
        try {
            System.out.println("Escrevendo arquivo...");
            byte[] byteArray = conteudo.getBytes();
            FileOutputStream in = new FileOutputStream(caminhoArquivoDestino) ;  
            in.write(byteArray);
            in.close();
         } catch (IOException ex) {
            System.out.println("ERRO: " + ex.getMessage());
        }
    }
    
    public void expansaoChaves() {
        
    }
    
    public static void main(String[] args) {
        //Trabalho trabalho = new Trabalho();
        //trabalho.executarLeituraDadosIniciais();
        //trabalho.transformaChaveEmBytes();
        
        //trabalho.lerArquivo();
        //trabalho.escreverArquivo();
        try {
            String chave = "A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P";            
            //String chave = "20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248";
            //String[] archaveInt = converteChaveString(chave, false);
            //String chaveInt = Arrays.toString(archaveInt);
            String chaveInt = converteChaveStringToByte(chave, false);
           
            insereLog("Chave: " + chaveInt);
            popularMatrizChave(chaveInt);
            imprimeMatriz(matrizChaveInt);
            imprimeMatrizHex(matrizChaveHex);
           
            //------------------------------------------------------------------
            //  EXPANSÂO DE CHAVE
            //------------------------------------------------------------------
            insereLog("--- Expansão de chave ---");
            String[] coluna3 = extrairColunaArray(matrizChaveHex, 3);            
           
            insereLog("Imprime coluna 3");
            imprimeColunaVetor(coluna3);
           
            insereLog("--- parte 2 ? rotacionar os bytes --- byte0->byte1  byte1->byte2   byte2->byte3  byte3->byte0 ");                        
            String[] colunaRotacionada = parte2_rotacionaColunaVetor_RotWord(coluna3);
            insereLog("Imprime coluna 3 Rotacionada");
            imprimeColunaVetor(colunaRotacionada);
           
            insereLog("--- parte 3 ? substituição de palavra --- converte na SBOX ");                        
            String[] colunaSubstituida = parte3_substituiPalavra_SubstWord(colunaRotacionada);
            imprimeColunaVetor(colunaSubstituida);
             
            insereLog("--- parte 4 ? gera a RoundConstant --- ");
            String[] colunaRoundConstant = parte4_getRoundConstant(1);
            imprimeColunaVetor(colunaRoundConstant);
           
            insereLog("--- parte 5 ? XOR com a RoundConstant --- ");
            String[] colunaXorRoundConstant = parte5_XorRoundConstant(colunaSubstituida, colunaRoundConstant);
            imprimeColunaVetor(colunaXorRoundConstant);
           
            insereLog("--- parte 6 ? gerarPrimeiraPalavraProximaRondKey --- ");                        
            String[] primeiraColunaProximaRoundKey = parte6_XORRoundKeyAnterior(5, colunaXorRoundConstant);
            imprimeColunaVetor(primeiraColunaProximaRoundKey);
           
            //insere coluna matrix
            String[][] matrix2 = new String[4][4];
            matrix2[0][0] = "A";
            matrix2[0][1] = "B";
            matrix2[0][2] = "C";
            matrix2[0][3] = "D";
            imprimeMatrizHex(matrix2);
           
            insereColunaMatriz(matrix2, primeiraColunaProximaRoundKey, 0);
            imprimeMatrizHex(matrix2);
           
           
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}