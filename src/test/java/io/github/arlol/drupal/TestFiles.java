package io.github.arlol.drupal;

import java.io.IOException;

import org.springframework.core.io.ClassPathResource;

public abstract class TestFiles {

	private TestFiles() {
	}

	public static byte[] readAllBytes(String path) throws IOException {
		return new ClassPathResource(path).getInputStream().readAllBytes();
	}

}
