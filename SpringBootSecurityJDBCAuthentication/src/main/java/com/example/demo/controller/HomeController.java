package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

	@GetMapping("/home")
	public String showHomePage() {
		return "HomePage";
	}

	@GetMapping("/welcome")
	public String showWelcomePage() {
		return "welcomePage";
	}

	@GetMapping("/emp")
	public String showEmpPage() {
		return "empPage";
	}

	@GetMapping("/admin")
	public String showadminPage() {
		return "adminPage";
	}
	
	@GetMapping("/denied")
	public String showWrongPage() {
		return "deniedPage";
	}
}
