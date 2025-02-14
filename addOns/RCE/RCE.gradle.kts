description = "Pranaya Sinha: Active Scan Demo"
version = "1.1.1"

zapAddOn {
    addOnName.set("PranayaActiveScan")
    zapVersion.set("2.10.0")

    manifest {
        author.set("Pranaya Sinha")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
