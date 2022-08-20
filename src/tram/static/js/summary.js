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
    var spinner = document.getElementById('offcanvas_spinner');
    var offcanvas_body = document.getElementById('offcanvas-body-IOC-content');
    var offcanvas_title = document.getElementById('offcanvas-title');
    var accordion = document.getElementById('accordion-body-IOC');
    
    accordion.innerHTML = '';
    offcanvas_title.innerHTML = IOC_value;
    offcanvas_title.style.color = "black";
    
    spinner.hidden = false;
    offcanvas_body.hidden = true;

    $.ajax({    
        type: "GET",
        url: `/api/IOCDetails/?IOC_value=${IOC_value}&IOC_type=${IOC_type_name}`,
        dataType: "json",
        success: function (IOC_details) {
            offcanvas_body.hidden = false;
            spinner.hidden = true;
            offcanvas_title.innerHTML = IOC_value + ' - ' + IOC_details['info'];

            if (IOC_details['response_code'] == -1) {
                offcanvas_title.style.color = "red";
            } else if (IOC_details['response_code'] == 0) {
                offcanvas_title.style.color = "green";
            } else if (IOC_details['response_code'] == 1) {
                offcanvas_title.style.color = "red";
                accordion.innerHTML += '<h4>AlienVault Pulses:</h4>';   // TODO [ADD GENERIC INFO]
                for (pulseIndex in IOC_details['result']['pulse_info']['pulses']){
                    pulse = IOC_details['result']['pulse_info']['pulses'][pulseIndex]
                    accordion.innerHTML += 
                    '\
                    <div class="accordion-item">\
                        <h2 class="accordion-header" id="flush-' + pulse['id'] + '">\
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#flush-collapse-' + pulse['id'] + '" aria-expanded="false" aria-controls="flush-collapseOne">' + pulse['name'] + '</b>&nbsp;<small style="font-size: .675em;">[' + pulse['id']  + ']</small></button>\
                        </h2>\
                        <div id="flush-collapse-' + pulse['id'] + '" class="accordion-collapse collapse" aria-labelledby="flush-headingOne" data-bs-parent="#offcanvas-body-IOC-content">\
                            <div class="accordion-body">\
                                <div class="row">\
                                    <div class="col-6">\
                                        <ul class="list-group">\
                                            <li class="list-group-item"><b>ID:</b> ' + pulse['id'] + ' </li>\
                                            <li class="list-group-item"><b>Tags:</b> ' + JSON.stringify(pulse['author']) + ' </li>\
                                            <li class="list-group-item"><b>Description:</b> ' + pulse['description'] + ' </li>\
                                            <li class="list-group-item"><b>Created:</b> ' + pulse['created'] + ' </li>\
                                            <li class="list-group-item"><b>Modified:</b> ' + pulse['modified'] + ' </li>\
                                        </ul>\
                                    </div>\
                                    <div class="col-6">\
                                        <ul class="list-group">\
                                            <li class="list-group-item"><b>References:</b> ' + pulse['references'] + ' </li>\
                                            <li class="list-group-item"><b>Indicator type counts: </b> ' + JSON.stringify(pulse['indicator_type_counts'])  + ' </li>\
                                            <li class="list-group-item"><b>Malware families:</b> ' + JSON.stringify(pulse['malware_families']) + ' </li>\
                                            <li class="list-group-item"><b>Attack ids:</b> ' + JSON.stringify(pulse['attack_ids']) + ' </li>\
                                            <li class="list-group-item"><b>Targeted countries:</b> ' + pulse['targeted_countries'] + ' </li>\
                                        </ul>\
                                    </div>\
                                </div>\
                            </div>\
                        </div>\
                    </div>\
                    '
                }
            } else if (IOC_details['response_code'] == 2) {
                offcanvas_title.style.color = "orange";
            } else if (IOC_details['response_code'] == 3) {
                offcanvas_title.style.color = "green";
                accordion.innerHTML += '<h4>Validations:</h4>'
                for (validationIndex in IOC_details['validations']) {
                    validation = IOC_details['validations'][validationIndex];
                    accordion.innerHTML += '\
                        <div>\
                            <ul>\
                                <li> <b>Name:</b> ' + validation['name'] + '  </li>\
                                <li> <b>Message:</b> ' + validation['message'] + '  </li>\
                                <li> <b>Source:</b> ' + validation['source'] + '  </li>\
                            </ul>\
                        </div><br>'
                }
                
            }
        },
        failure: function (data) {
            console.log(`Failure: ${data}`);
            offcanvas_title.innerHTML = 'HTTP ERROR';
            offcanvas_body.hidden = false;
            spinner.hidden = true;
        }
    });
}
