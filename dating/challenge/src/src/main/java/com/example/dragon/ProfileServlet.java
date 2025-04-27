package com.example.dragon;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.beans.XMLDecoder;
import java.io.IOException;

@WebServlet("/ProfileServlet")
public class ProfileServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/plain");

        try {
            XMLDecoder decoder = new XMLDecoder(request.getInputStream());
            Object dragonData = decoder.readObject();
            decoder.close();

            response.getWriter().write("Profile received for: " + dragonData.toString());
        } catch (Exception e) {
            response.getWriter().write("Error processing profile: " + e.getMessage());
        }
    }
}
