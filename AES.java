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
x  c) Permitir que o usuário forneça a chave de criptografia. Deve ser um campo texto em que possa ser fornecido os
   valores dos bytes da chave, separando os bytes por vírgula. Por exemplo: este é um texto que deve ser possível 
   fornecer para indicar os bytes da chave: ?20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248?;
x  d) Implementar o modo de operação ECB e tamanho de chave de 128 bits;
x  e) Implementar o modo de preenchimento PKCS#7;
x  f) A solução não pode ser cópia de outros autores e deve utilizar a abordagem vista em sala de aula
  
  */

public class AES {
    
    enum LogLevel {
        NORMAL, DEBUG;
    }
    
    final int[][] sbox = {        
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
    
    final int[][] galoisL = {
            //  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
            {0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03},  // 0
            {0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1},  // 1
            {0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78},  // 2
            {0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e},  // 3
            {0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38},  // 4
            {0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10},  // 5
            {0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba},  // 6
            {0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57},  // 7
            {0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8},  // 8
            {0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0},  // 9
            {0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7},  // A
            {0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d},  // B
            {0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1},  // C
            {0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab},  // D
            {0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5},  // E
            {0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07}}; // F
    
    final int[][] galoisE = {
            //  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
            {0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35},  // 0
            {0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa},  // 1
            {0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31},  // 2
            {0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd},  // 3
            {0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88},  // 4 
            {0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a},  // 5
            {0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3},  // 6
            {0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0},  // 7
            {0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41},  // 8
            {0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75},  // 9
            {0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80},  // A
            {0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54},  // B
            {0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca},  // C
            {0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e},  // D
            {0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17},  // E
            {0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01}}; // F
            
    
    final Integer[][] vMultiplicationMatrix = {
            //  0     1     2     3
            {0x02, 0x03, 0x01, 0x01},  // 0
            {0x01, 0x02, 0x03, 0x01},  // 1
            {0x01, 0x01, 0x02, 0x03},  // 2
            {0x03, 0x01, 0x01, 0x02}}; // 3
   
    final int[] vRoundKey = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
   
    Integer[][] matrizChaveInt = new Integer[4][4];
    String[][] matrizChaveHex = new String[4][44];
    Integer[][] matrizEstadoTextoSimplesInt;
    String[][] matrizEstadoTextoSimplesHex;
    String[][] matrizEstadoSaidaHex;
    LogLevel logLevel = LogLevel.NORMAL;
    Scanner scanner = new Scanner(System.in);
    String caminhoArquivoEntrada;
    String caminhoArquivoDestino;
    String conteudo = "teste";
    String chave;
    int tamanhoMatrizEstado;
    int quantidadeBlocos128Bits;
    byte[] vetorSaidaTextoCifradoByte;
    
    private void popularMatrizChave() {
        String[] matrizChave = chave.split(",");
        int cont = 0;
        for (int lin = 0; lin < 4; lin++) {
           for (int col = 0; col < 4; col++) {
                Integer valor = Integer.parseInt(matrizChave[cont]);
                //System.out.println("l" + lin + " c" + col + " - " + valor);
                // esta invertido porque tem que preencher coluna pra baixo, ao inves de ir ao lado
                matrizChaveInt[col][lin] = valor;
                matrizChaveHex[col][lin] = Integer.toHexString(valor);
                cont++;
           }
       }
    }
    
    private void popularMatrizEstadoTextoSimples() {
        String[] matrizEstado = conteudo.split(",");
        tamanhoMatrizEstado = matrizEstado.length / 4;
        quantidadeBlocos128Bits = tamanhoMatrizEstado / 4;

        matrizEstadoTextoSimplesInt = new Integer[4][tamanhoMatrizEstado];
        matrizEstadoTextoSimplesHex = new String[4][tamanhoMatrizEstado];
        matrizEstadoSaidaHex = new String[4][tamanhoMatrizEstado];
        
        int cont = 0;
        for (int lin = 0; lin < 4; lin++) {
           for (int col = 0; col < tamanhoMatrizEstado; col++) {
                Integer valor = Integer.parseInt(matrizEstado[cont]);
                //System.out.println("l" + lin + " c" + col + " - " + valor);
                // esta invertido porque tem que preencher coluna pra baixo, ao inves de ir ao lado
                matrizEstadoTextoSimplesInt[col][lin] = valor;
                matrizEstadoTextoSimplesHex[col][lin] = Integer.toHexString(valor);
                cont++;
           }
       }
    }
   
    private void imprimeMatrizInt(Integer[][] matriz) {
        System.out.println("\nMatriz integer");
        for (int linha = 0; linha < matriz.length; linha++) {
            for (int col = 0; col < matriz[0].length; col++) {
                System.out.printf("%3d   ", matriz[linha][col]);
                if (col == 3) {
                    System.out.print("\n");
                }
           }
       }
        System.out.println("\n");
    }
    
    private void imprimeMatrizHex(String[][] matriz) {
        System.out.println("Matriz HEX");
        for (int col = 0; col < matriz[0].length; col++) {
            //System.out.print("w"+ col + "    ");
            System.out.printf("w%-5s",col);
        }
        System.out.print("\n");
        
        for (int lin = 0; lin < matriz.length; lin++) {
           for (int col = 0; col < matriz[0].length; col++) {
               //System.out.println("linha: " + lin + " coluna:" + col);
                System.out.printf("%-4s  ", matriz[lin][col]);
                if (col == matriz[0].length-1) {
                    System.out.print("\n");
                }
           }
       }
       System.out.println("\n");
    }
   
    private String converteChaveStringToByte(String chave, Boolean isHex) {
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
   
    private void insereLog(String mensagem) {
        Date dataHoraAtual = new Date();
        String hora = new SimpleDateFormat("HH:mm:ss").format(dataHoraAtual);
        //System.out.println(hora + ": " + mensagem);
        System.out.println(mensagem);
    }

    private String[] extrairColunaArray(String[][] ar, Integer coluna) {
        String[] arTemp = new String[ar.length];
        for (int i = 0; i < arTemp.length; i++) {
            arTemp[i] = ar[i][coluna];
        }
        return arTemp;
    }
   
    private void imprimeColunaVetor(String [] arColuna) {        
        for (int i = 0; i < arColuna.length; i++) {
            System.out.println(arColuna[i]);
        }
    }    
   
    private String[] expansaoChave_parte2_rotacionaColunaVetor_RotWord(String[] vetor) {
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
   
    private String substituiSbox(String letra) {
        Character primeira;
        Character segunda;        
        if (letra.length() == 1) {
            primeira = '0';
            segunda = letra.charAt(0);
        } else {
            primeira = letra.charAt(0);
            segunda = letra.charAt(1);        
        }
        Integer linha = hexToIntegerSBox(primeira);
        Integer coluna = hexToIntegerSBox(segunda);
       
        Integer valor = sbox[linha][coluna];
       
        return Integer.toHexString(valor);
    }
   
    private Integer hexToIntegerSBox(Character c) {
       
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
   
    private String getRoundKey(Integer value) {
        return Integer.toHexString(vRoundKey[value]);
    }
   
    private String[] expansaoChave_parte3_substituiPalavra_SubstWord(String[] vetor) {
        String[] arTemp = new String[vetor.length];
        for (int i = 0; i < vetor.length; i++) {            
            arTemp[i] = substituiSbox(vetor[i]);
        }
        return arTemp;
    }
   
    private String[] expansao_Chave_parte4_getRoundConstant(Integer roundKey) {
        String[] vetor = new String[4];
        vetor[0] = getRoundKey(roundKey);
        vetor[1] = "0";
        vetor[2] = "0";                
        vetor[3] = "0";                
        return vetor;
    }
   
    private String[] expansaoChave_parte5_XorRoundConstant(String[] colunaSubstituida, String[] colunaRoundConstant) {
        String[] arTemp = new String[colunaSubstituida.length];
       
        arTemp[0] = XOR2Hex(colunaSubstituida[0], colunaRoundConstant[0]);
        arTemp[1] = XOR2Hex(colunaSubstituida[1], colunaRoundConstant[1]);        
        arTemp[2] = XOR2Hex(colunaSubstituida[2], colunaRoundConstant[2]);        
        arTemp[3] = XOR2Hex(colunaSubstituida[3], colunaRoundConstant[3]);        
       
        return arTemp;
    }
   
    private Integer HexToInt(String value) {
        return Integer.parseInt(value, 16);
    }
   
    private String XOR2Hex(String value1, String value2) {
        int n1 = HexToInt(value1);
        int n2 = HexToInt(value2);
        int n3 = n1 ^ n2;            
        return Integer.toHexString(n3);
    }
    
    private String XOR4Hex(String value1, String value2, String value3, String value4) {
        int n1 = HexToInt(value1);
        int n2 = HexToInt(value2);
        int n3 = HexToInt(value3);
        int n4 = HexToInt(value4);
        int n5 = n1 ^ n2 ^ n3 ^ n4;
        return Integer.toHexString(n5);
    }
    
    private String SUM2HexGalois(String value1, String value2) {
        int n1 = HexToInt(value1);
        int n2 = HexToInt(value2);
        int n3 = n1 + n2;     

        // Observação: se o resultado da soma ultrapassar 0xFF, faz-se ajuste: resultado  = 0xFF
        if (n3 >= 255) {
            n3 = 255;
        }
  
        // multiplica galois
        // - Se um dos termos for 0, o resultado da multiplicação é 0.
        if ((n1 == 0) || (n2 == 0)) {
            n3 = 0;
        }        
        // ? Se um dos termos for 1, o resultado da multiplicação é igual ao outro termo
        if ((n1 == 1)) {
            n3 = n2;
        }
        if ((n2 == 1)) {
            n3 = n1;
        }
        
        return Integer.toHexString(n3);
    }
   
    private String[] expansaoChave_parte6_XORRoundKeyAnterior(Integer colunaAtual, String[] colunaXorRoundConstant) {
        String[] coluna1Anterior = extrairColunaArray(matrizChaveHex, colunaAtual-1-4);
        String[] arTemp = new String[colunaXorRoundConstant.length];
       
        arTemp[0] = XOR2Hex(coluna1Anterior[0], colunaXorRoundConstant[0]);
        arTemp[1] = XOR2Hex(coluna1Anterior[1], colunaXorRoundConstant[1]);
        arTemp[2] = XOR2Hex(coluna1Anterior[2], colunaXorRoundConstant[2]);
        arTemp[3] = XOR2Hex(coluna1Anterior[3], colunaXorRoundConstant[3]);      
       
        return arTemp;
    }
   
    private void insereColunaMatriz(String[][] matriz, String[] vetor, Integer coluna) {        
        for (int i = 0; i < vetor.length; i++) {
            matriz[i][coluna] = vetor[i];
        }
    }        
    
    public AES() {
        
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
            byte[] arByte = entrada.readAllBytes();
            int umByte;
            String sConteudo = "";
            for (int i = 0; i < arByte.length; i++) {
                umByte = arByte[i];
                sConteudo += Integer.toString(umByte);
                if (i < arByte.length-1) {
                    sConteudo += ",";
                }
            }
            conteudo = sConteudo;
            System.out.println("\nConteúdo arquivo:\n" + sConteudo);
        } catch (IOException ex) {
            System.out.println("ERRO: " + ex.getMessage());
        }
    }
    
    public void escreverArquivo() {
        try {
            System.out.println("\nEscrevendo arquivo: " + caminhoArquivoDestino);
            byte[] byteArray = vetorSaidaTextoCifradoByte;
            FileOutputStream in = new FileOutputStream(caminhoArquivoDestino) ;  
            in.write(byteArray);
            in.close();
         } catch (IOException ex) {
            System.out.println("ERRO: " + ex.getMessage());
        }
    }

    private void insereVetorMatriz(String[][] matriz, String[] vetor, Integer coluna) {
        for (int i = 0; i < vetor.length; i++) {
            matriz[i][coluna] = vetor[i];    
        }
    }
    
    private void expansaoChave_parte7_finalizaPreenchimentoMatrizChaveHex(Integer coluna) {
        int w5 = coluna+2;
        int w1 = coluna-2;  
        int w4 = coluna+1;
        //System.out.println("w5:" + w5 + " w1:" + w1 + " w4:" + w4);
        for (int lin = 0; lin < matrizChaveHex.length; lin++) {
            matrizChaveHex[lin][w5] = XOR2Hex(matrizChaveHex[lin][w1], matrizChaveHex[lin][w4]);
            matrizChaveHex[lin][w5+1] = XOR2Hex(matrizChaveHex[lin][w1+1], matrizChaveHex[lin][w4+1]);
            matrizChaveHex[lin][w5+2] = XOR2Hex(matrizChaveHex[lin][w1+2], matrizChaveHex[lin][w4+2]);
        }
        //w5 = w1 XOR w4
        //System.out.println("w5:" + XOR2Hex("45", "6f"));
        //w6 = w2 XOR w5
        //System.out.println("w6:" + XOR2Hex("49", "2a"));
        //w7 = w3 XOR w6
        //System.out.println("w7:" + XOR2Hex("4d", "63"));
    }
    
    public Integer intToSignedByte(int value) {
        Byte b = (byte) value;
        return b.intValue();
    }
    
    public String converteStringSignedByte(String value, Boolean toChar) {
        String[] arTemp = value.split(",");
        String sTemp = "";
        for (int i = 0; i < arTemp.length; i++) {
            int valor = Integer.parseInt(arTemp[i]);
            Integer unsignedInt = intToSignedByte(valor);
            if (toChar) {
                sTemp += (char)valor;
            } else {
                sTemp += unsignedInt.toString();
            }
            if (i+1 < arTemp.length) {
                sTemp += ",";
            }
        }
        return sTemp;
    }
    
    private void expandirChave(Boolean isSlideMode) {
        String chaveTeste;
        String chaveInt;
        
        if (isSlideMode) {
            chaveTeste = "A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P";            
            chaveInt = converteChaveStringToByte(chaveTeste, false);  
            chave = chaveInt;
        } else {
            chaveTeste = "20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248";
            //chaveIntSigned = converteStringSignedByte(chaveTeste2, false);
            //           "20,1,94,33,-57,0,48,9,31,94,112,40,59,30,100,-8";
            chave = chaveTeste;
        }
        
        insereLog("Chave: " + chave);
        
        popularMatrizChave();
        imprimeMatrizInt(matrizChaveInt);
        imprimeMatrizHex(matrizChaveHex);

        insereLog("--- Expansão de chave ---");
        Integer roundKey = 1;
        for (int i = 1; i <= 10; i++) {
            addRoundKey(i);    
        }
        imprimeMatrizHex(matrizChaveHex);
    }
    
    private void addRoundKey(Integer roundKey) {
        insereLog("---  ROUND KEY " + roundKey + " -----------------------------");
        Integer coluna = (roundKey * 4)-1;
        
        insereLog("  --- parte 1 - copia palavra da roundkey anterior - w" + coluna);                        
        String[] ultimaColuna = extrairColunaArray(matrizChaveHex, coluna);            
        imprimeColunaVetor(ultimaColuna);
       
        insereLog("  --- parte 2 - rotacionar os bytes --- byte0->byte1  byte1->byte2   byte2->byte3  byte3->byte0 ");                        
        String[] colunaRotacionada = expansaoChave_parte2_rotacionaColunaVetor_RotWord(ultimaColuna);
        insereLog("Imprime coluna " + coluna + " rotacionada");
        imprimeColunaVetor(colunaRotacionada);

        insereLog("  --- parte 3 - substituição de palavra --- converte na SBOX ");                        
        String[] colunaSubstituida = expansaoChave_parte3_substituiPalavra_SubstWord(colunaRotacionada);
        imprimeColunaVetor(colunaSubstituida);

        insereLog("  --- parte 4 - gera a RoundConstant da RoundKey " + roundKey + " --- ");
        String[] colunaRoundConstant = expansao_Chave_parte4_getRoundConstant(roundKey);
        imprimeColunaVetor(colunaRoundConstant);

        insereLog("  --- parte 5 - XOR com a RoundConstant --- ");
        String[] colunaXorRoundConstant = expansaoChave_parte5_XorRoundConstant(colunaSubstituida, colunaRoundConstant);
        imprimeColunaVetor(colunaXorRoundConstant);

        insereLog("  --- parte 6 - gerarPrimeiraPalavraProximaRondKey --- ");                        
        String[] primeiraColunaProximaRoundKey = expansaoChave_parte6_XORRoundKeyAnterior(5, colunaXorRoundConstant);
        imprimeColunaVetor(primeiraColunaProximaRoundKey);

        insereColunaMatriz(matrizChaveHex, primeiraColunaProximaRoundKey, coluna+1);
        
        int colunaInicial = coluna+2;
        int colunaFinal = coluna+4;
        insereLog("  --- parte 7 - gerar w" + colunaInicial + " a w" + colunaFinal + " --- ");                        
        expansaoChave_parte7_finalizaPreenchimentoMatrizChaveHex(coluna);
    }
    
    private void cifrarBloco_parte1_XOR(String[][] matrizSaida, String[][] matrizChaveHex, String[][] matrizEstadoTextoSimplesHex, int blocoInicio) {
        for (int col = blocoInicio; col < blocoInicio+4; col++) {
            matrizSaida[0][col] = XOR2Hex(matrizChaveHex[0][col], matrizEstadoTextoSimplesHex[0][col]);
            matrizSaida[1][col] = XOR2Hex(matrizChaveHex[1][col], matrizEstadoTextoSimplesHex[1][col]);
            matrizSaida[2][col] = XOR2Hex(matrizChaveHex[2][col], matrizEstadoTextoSimplesHex[2][col]);
            matrizSaida[3][col] = XOR2Hex(matrizChaveHex[3][col], matrizEstadoTextoSimplesHex[3][col]);
        }
    }
    
    private void cifrarBloco_parte2_SubBytes(String[][] matrizSaida, String[][] matrizChaveHex, int blocoInicio) {
        for (int col = blocoInicio; col < blocoInicio+4; col++) {
            matrizSaida[0][col] = substituiSbox(matrizSaida[0][col]);
            matrizSaida[1][col] = substituiSbox(matrizSaida[1][col]);
            matrizSaida[2][col] = substituiSbox(matrizSaida[2][col]);
            matrizSaida[3][col] = substituiSbox(matrizSaida[3][col]);
        }
    }
    
    private void cifrarBloco_parte3_ShiftRows(String[][] matrizSaida, int blocoInicio) {
        int col = blocoInicio;
        String sCol0, sCol1, sCol2, sCol3;
        // ?0,0 ?0,1 ?0,2 ?0,3 -> ?0,0 ?0,1 ?0,2 ?0,3
        
        // ?1,0 ?1,1 ?1,2 ?1,3 -> ?1,1 ?1,2 ?1,3 ?1,0
        sCol0 = matrizSaida[1][col];
        sCol1 = matrizSaida[1][col+1];
        sCol2 = matrizSaida[1][col+2];
        sCol3 = matrizSaida[1][col+3];
        matrizSaida[1][col] = sCol1;
        matrizSaida[1][col+1] = sCol2;
        matrizSaida[1][col+2] = sCol3;
        matrizSaida[1][col+3] = sCol0;
        
        // ?2,0 ?2,1 ?2,2 ?2,3 -> ?2,2 ?2,3 ?2,0 ?2,1
        sCol0 = matrizSaida[2][col];
        sCol1 = matrizSaida[2][col+1];
        sCol2 = matrizSaida[2][col+2];
        sCol3 = matrizSaida[2][col+3];
        matrizSaida[2][col] = sCol2;
        matrizSaida[2][col+1] = sCol3;
        matrizSaida[2][col+2] = sCol0;
        matrizSaida[2][col+3] = sCol1;
        
        // ?3,0 ?3,1 ?3,2 ?3,3 -> ?3,3 ?3,0 ?3,1 ?3,2
        sCol0 = matrizSaida[3][col];
        sCol1 = matrizSaida[3][col+1];
        sCol2 = matrizSaida[3][col+2];
        sCol3 = matrizSaida[3][col+3];
        matrizSaida[3][col] = sCol3;
        matrizSaida[3][col+1] = sCol0;
        matrizSaida[3][col+2] = sCol1;
        matrizSaida[3][col+3] = sCol2;
    }
    
    private String substituiGaloisL(String letra) {
        Character primeira;
        Character segunda;        
        if (letra.length() == 1) {
            primeira = '0';
            segunda = letra.charAt(0);
        } else {
            primeira = letra.charAt(0);
            segunda = letra.charAt(1);        
        }
        Integer linha = hexToIntegerSBox(primeira);
        Integer coluna = hexToIntegerSBox(segunda);
       
        Integer valor = galoisL[linha][coluna];
       
        return Integer.toHexString(valor);
    }
    
    private String substituiGaloisE(String letra) {
        Character primeira;
        Character segunda;        
        if (letra.length() == 1) {
            primeira = '0';
            segunda = letra.charAt(0);
        } else {
            primeira = letra.charAt(0);
            segunda = letra.charAt(1);        
        }
        Integer linha = hexToIntegerSBox(primeira);
        Integer coluna = hexToIntegerSBox(segunda);
       
        Integer valor = galoisE[linha][coluna];
       
        return Integer.toHexString(valor);
    }    
    
    public String multiplicaGalois(String r, String m) {
        String g = substituiGaloisL(r);
        String ms = substituiGaloisL(m);
        String resultado = SUM2HexGalois(g, ms);
        String resultadoE = substituiGaloisE(resultado);
       
        return resultadoE;
    }
    
    private void cifrarBloco_parte4_MixColumns(String[][] matrizSaida, int blocoInicio) {
        
        for (int col = blocoInicio; col < 4; col++) {
            String[] arColuna = extrairColunaArray(matrizSaida, col);
            String[] arResultadoB = new String[4];

            String r1 = arColuna[0];
            String r2 = arColuna[1];
            String r3 = arColuna[2];
            String r4 = arColuna[3];

            for (int lin = 0; lin < 4; lin++) {
                String mGalois1 = vMultiplicationMatrix[lin][0].toString();
                String mGalois2 = vMultiplicationMatrix[lin][1].toString();
                String mGalois3 = vMultiplicationMatrix[lin][2].toString();
                String mGalois4 = vMultiplicationMatrix[lin][3].toString();
                /*
                System.out.println("r1: " + r1 + " m: " + mGalois1);
                System.out.println("r2: " + r2 + " m: " + mGalois2);
                System.out.println("r3: " + r3 + " m: " + mGalois3);
                System.out.println("r4: " + r4 + " m: " + mGalois4);
                */
                String resultado1 = multiplicaGalois(r1, mGalois1);
                String resultado2 = multiplicaGalois(r2, mGalois2);
                String resultado3 = multiplicaGalois(r3, mGalois3);
                String resultado4 = multiplicaGalois(r4, mGalois4);
                /*System.out.println(resultado1);
                System.out.println(resultado2);
                System.out.println(resultado3);
                System.out.println(resultado4);
                */
                String resultadoFinalB1 = XOR4Hex(resultado1, resultado2, resultado3, resultado4);
                //System.out.println("resultado final linha " + lin + ": " + resultadoFinalB1);
                arResultadoB[lin] = resultadoFinalB1;
            }
            //w0 1c e0 7d 36
            insereColunaMatriz(matrizSaida, arResultadoB, col);
        }
    }
    
    private void cifrarBloco_parte5_AddRoundKey(String[][] matrizSaida, String[][] matrizSaida2, String[][] matrizChaveHex, int blocoInicio) {
        for (int col = blocoInicio; col < blocoInicio+4; col++) {
            matrizSaida[0][col] = XOR2Hex(matrizSaida2[0][col], matrizChaveHex[0][col]);
            matrizSaida[1][col] = XOR2Hex(matrizSaida2[1][col], matrizChaveHex[1][col]);
            matrizSaida[2][col] = XOR2Hex(matrizSaida2[2][col], matrizChaveHex[2][col]);
            matrizSaida[3][col] = XOR2Hex(matrizSaida2[3][col], matrizChaveHex[3][col]);
        }
    }
    
    private void extrairTextoCifradoHex(String[][] matrizSaida) {
        //System.out.println("\n\nTamanho: " + tamanhoSaida);
        
        int cont = 0;
        // verifica se tem algum valor null na matriz
        for (int lin = 0; lin < 3; lin++) {
           for (int col = 0; col < tamanhoMatrizEstado; col++) {
                if (matrizSaida[col][lin] == null) {
                    break;
                }
                cont++;
           }
        }
        String[] vetorSaidaTextoCifradoHex = new String[cont];
        cont = 0;
        for (int lin = 0; lin < 3; lin++) {
           for (int col = 0; col < tamanhoMatrizEstado; col++) {
                //System.out.print(matrizSaida[col][lin] + ",");
                vetorSaidaTextoCifradoHex[cont] = matrizSaida[col][lin];
                cont++;
           }
       } 
       
       //5d,a2,3e,72,68,d3,fd,62,70,81,36,8d,7e,ef,2e,2a 
       //resultado deverá ser em blocos de 16 bytes (32 caracteres)
       vetorSaidaTextoCifradoHex = PKCS7PaddingHexString(vetorSaidaTextoCifradoHex);
       vetorSaidaTextoCifradoByte = new byte[vetorSaidaTextoCifradoHex.length];
       
        for (int i = 0; i < vetorSaidaTextoCifradoHex.length; i++) {
            String hex = vetorSaidaTextoCifradoHex[i];
            int iHex = Integer.decode("0x"+hex);
            vetorSaidaTextoCifradoByte[i] = (byte)iHex;
        }
       
        //String hex = "a2";
        //int convertedValue = Integer.decode("0x"+hex);
        
        //Byte b = (byte) convertedValue;
        //System.out.print(convertedValue + " byte: " + b);
         
        //Integer a = Integer.parseInt("ca", 64);
        //Byte b = Byte.parseByte("ca", 64);
        //System.out.println("a: " + a + " b: " + b );
       
    }
    
     private String[] PKCS7PaddingHexString(String[] matrizEntrada) {    
        // pega o vetor e valida o tamanho.
        // - Se for maior que multiplo de 16, cria novo bloco e preenche
        // - Se for menos que multiplo de 16, preenche o restante
        int tamanho = matrizEntrada.length;
        int novoTamanho = tamanho;
        int resto = 0;
        if (tamanho < 16) {
            novoTamanho = 16;
            resto = 16 - tamanho;
        } else {
            resto = (tamanho % 16);
            if (resto > 0) {
                novoTamanho = tamanho - resto + 16;
                resto = novoTamanho - tamanho;
            }
        }
       
        String sHexPadResto = Integer.toHexString(resto);        
        String[] finalPad = new String[novoTamanho];
        for (int i = 0; i < novoTamanho; i++) {
            if (i < matrizEntrada.length) {
                finalPad[i] = matrizEntrada[i];
            } else {
                finalPad[i] = sHexPadResto;
            }
        }
        return finalPad;
    } 
    
    private void cifrarBlocos(Boolean isSlideMode) {
        insereLog("--- Cifrar Blocos ---");
        popularMatrizEstadoTextoSimples();
        imprimeMatrizInt(matrizEstadoTextoSimplesInt);
        imprimeMatrizHex(matrizEstadoTextoSimplesHex);
        
        //efetua leitura bloco a bloco de 128 bits, 4 blocos de 4 bytes
        int bloco = 0;
        while (bloco < tamanhoMatrizEstado) {
            cifrarBloco_parte1_XOR(matrizEstadoSaidaHex, matrizChaveHex, matrizEstadoTextoSimplesHex, bloco);
            insereLog("  -- Cifra Parte 1 - XOR --");
            imprimeMatrizHex(matrizEstadoSaidaHex);
            insereLog("  -- Cifra Parte 2 - SubBytes --");
            cifrarBloco_parte2_SubBytes(matrizEstadoSaidaHex, matrizChaveHex, bloco);
            imprimeMatrizHex(matrizEstadoSaidaHex);
            insereLog("  -- Cifra Parte 3 - ShiftRows --");
            cifrarBloco_parte3_ShiftRows(matrizEstadoSaidaHex, bloco);
            insereLog("  -- Cifra Parte 4 - MixColumns --");
            imprimeMatrizHex(matrizEstadoSaidaHex);
            cifrarBloco_parte4_MixColumns(matrizEstadoSaidaHex, bloco);
            imprimeMatrizHex(matrizEstadoSaidaHex);
            insereLog("  -- Cifra Parte 5 - AddRoundKey --");
            cifrarBloco_parte5_AddRoundKey(matrizEstadoSaidaHex, matrizEstadoSaidaHex, matrizChaveHex, bloco);
            imprimeMatrizHex(matrizEstadoSaidaHex);
            
            bloco += 4;
        }
        extrairTextoCifradoHex(matrizEstadoSaidaHex);
    }
    
    public static void main(String[] args) {
        try {
            AES aes = new AES();
            aes.logLevel = LogLevel.DEBUG;
            // Se isSlideMode estiver como true, os dados de chave e conteúdo simulam os resultados do slide.
            // Se estiver como false, executa a chave e cifragem com dados iniciais.
            Boolean isSlideMode = false;
            
            // Para testar mais rápido pode-se comentar o método de executarLeituraDadosIniciais()
            // e fornecer os dados diretamente. chave, caminhoArquivoEntrada, caminhoArquivoDestino
            
            //aes.executarLeituraDadosIniciais();
            
            aes.caminhoArquivoEntrada = "c:\\temp\\entrada.txt";
            aes.caminhoArquivoDestino = "c:\\temp\\saida.dat";
            aes.lerArquivo();
            
            aes.expandirChave(isSlideMode);
            
            //68,69,83,69,78,86,79,76,86,73,77,69,78,84,79,33
            aes.conteudo = "68,69,83,69,78,86,79,76,86,73,77,69,78,84,79,33";
            aes.cifrarBlocos(isSlideMode);
            aes.escreverArquivo();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}