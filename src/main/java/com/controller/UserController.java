package com.controller;


import com.util.RSACoder;
import org.springframework.http.HttpRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Controller
@RequestMapping("/user")
public class UserController {

    @RequestMapping(value = "login",method = RequestMethod.POST)
    public String login(@RequestParam("password") String password, Model model, HttpServletRequest httpServletRequest){

        try {
            byte[] encryptPassword  = RSACoder.decryptByPrivateKey(Base64Utils.decodeFromString(password),Base64Utils.decodeFromString((String) httpServletRequest.getServletContext().getAttribute("priKey")));
            model.addAttribute("encryptPassword",password);
            model.addAttribute("password", new String(encryptPassword,"UTF-8"));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return "/password.jsp";
    }
}
