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

function getIndicatorInfo(IOC_value, IOC_type_name){
    console.log("HOlaaaaa", IOC_value, IOC_type_name)
    var spinner = document.getElementById('offcanvas_spinner');
    var text = document.getElementById('offcanvasBottomLabel').firstChild;
    var accordion = document.getElementById('accordion-body-IOC');
    text.data = IOC_value;
    
    spinner.hidden = false;

    $.ajax({    
        type: "GET",
        url: `/api/IOCDetails/?IOC_value=${IOC_value}&IOC_type=${IOC_type_name}`,
        dataType: "json",
        success: function (IOC_details) {
            console.log(IOC_details['pulse_info']);
            spinner.hidden = true;
            
            var $accordion_content = $('')
            
            for (pulse in IOC_details['pulse_info']){
                console.log(pulse)
                $accordion_content.append(
                    '<div class="accordion-item">\
                        <h2 class="accordion-header" id="flush-headingOne">\
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#flush-collapseOne" aria-expanded="false" aria-controls="flush-collapseOne"> ${sentence.id} </button>\
                        </h2>\
                        <div id="flush-collapseOne" class="accordion-collapse collapse" aria-labelledby="flush-headingOne" data-bs-parent="#accordionFlushExample">\
                        <div class="accordion-body">Placeholder content for this accordion, which is intended to demonstrate the <code>.accordion-flush</code> class. This is the first ites accordion body.</div>\
                        </div>\
                    </div>'
                );
            }

            accordion.innerHTML = $accordion_content;

        },
        failure: function (data) {
            console.log(`Failure: ${data}`);
        }
    });
}
