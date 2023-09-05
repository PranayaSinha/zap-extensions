description = "Pranaya Sinha: XPath Injection Test"
version = "1.1.1"

zapAddOn {
    addOnName.set("XPathInjectionTest")
    zapVersion.set("2.12.0")

    manifest {
        author.set("Pranaya")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
