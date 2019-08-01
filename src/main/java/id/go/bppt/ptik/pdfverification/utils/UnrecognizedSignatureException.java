/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pdfverification.utils;

/**
 *
 * @author Rachmawan
 */
public class UnrecognizedSignatureException extends Exception{
    
    private static final long serialVersionUID = 8947127337198049284L;
    public UnrecognizedSignatureException()
    {
    }
    
    public UnrecognizedSignatureException(String message)
    {
        super(message);
    }
}
