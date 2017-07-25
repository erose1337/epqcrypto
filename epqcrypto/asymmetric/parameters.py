P = 2162856158844985461289249749615925877431829137352992256594209856594439223948437451595264572685544280084236320535053554120005641780594461360999924859753577717547132577717151568525764429614531460013832016836541995858042528967106770950884707583431395743392711430035889618934835006665894726069789187736390533376523267

def calculate_parameter_sizes(security_level):
    """ usage: calculate_parameters_sizes(security_level) => short_inverse size, r size, s size, e size, P size
    
        Given a target security level, designated in bytes, return appropriate parameter sizes for instantiating the trapdoor. """
    short_inverse_size = (security_level * 2) + 1
    p_size = short_inverse_size * 2
    return short_inverse_size, security_level, security_level, security_level, p_size
    
