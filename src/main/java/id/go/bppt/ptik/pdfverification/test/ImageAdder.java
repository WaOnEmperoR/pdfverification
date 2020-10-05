/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package id.go.bppt.ptik.pdfverification.test;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author waone
 */
public class ImageAdder {
    public static final String SRC_PDF = "D:\\LAIN-LAIN\\Kenaikan Perekayasa Muda\\Fungsional 3B.pdf";
    public static final String DST_PDF = "D:\\LAIN-LAIN\\Kenaikan Perekayasa Muda\\Fungsional 3B_new.pdf";
    public static final String IMG_PATH = "C:\\Users\\waone\\Pictures\\1598318941131_heavy_rotation-min.png";
    
    public static void main(String[] args)
    {
        
        PdfReader reader;
        try {
            reader = new PdfReader(SRC_PDF);
            PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(DST_PDF));
            PdfContentByte content = stamper.getOverContent(1);
            
            Image image = Image.getInstance(IMG_PATH);

            // scale the image to 100px height
            image.scaleAbsoluteHeight(160);
            image.scaleAbsoluteWidth((image.getWidth() * 160) / image.getHeight());

            image.setAbsolutePosition(350, 660);
            content.addImage(image);

            stamper.close();
        } catch (IOException | DocumentException ex) {
            Logger.getLogger(ImageAdder.class.getName()).log(Level.SEVERE, null, ex);
        }       

        
    }
    
}
