var stored_sentences = {}; // stores `GET /api/sentences/` as a dict where {"sentence_id": {sentence}}

$( document ).ready(function() {    
    loadSentences();    
});

function loadSentences(active_sentence_id) {
    $.ajax({
        type: "GET",
        url: `/api/sentences/?report-id=${REPORT_ID}`,
        dataType: "json",
        success: function (sentences) {
            stored_sentences = storeSentences(sentences)
            mappings = getMappings(stored_sentences);
           
        },
        failure: function (data) {
            console.log(`Failure: ${data}`);
        }
    });
}

function storeSentences(sentences) {
    stored_sentences = {};
    for (var i = 0; i < sentences.length; i++) {
        var sentence = sentences[i];
        stored_sentences[sentence.id] = sentence;
        if (i == 0) {
            first_sentence_id = sentence.id
        }
        else if (i == sentences.length - 1) {
            last_sentence_id = sentence.id
        }
    }
    console.log(stored_sentences)
    return stored_sentences
}

function getMappings(stored_sentences){
    for (var sentence_id in stored_sentences) {
        
        var mappings = []
        var sentence = stored_sentences[sentence_id];
        console.log(sentence.disposition)
        for (var map_id in sentence.mappings){
            console.log(sentence.mappings[map_id])
            mappings.push(sentence.mappings[map_id])
        }
    
        return mappings

    }
}

function changeLabel(button_id){
    var text = document.getElementById(button_id).firstChild;
    text.data = text.data == "Display ATT&CK Matrix" ? "Hide ATT&CK Matrix" : "Display ATT&CK Matrix";
}

